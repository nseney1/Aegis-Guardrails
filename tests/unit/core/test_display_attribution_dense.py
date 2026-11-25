"""Dense colour must retain benign bytes without weakening attribution proofs."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import inspect
import json
import os
import re
import sys
import threading
import types

import pytest

from aegis_core import display_attribution as attribution, primitives
from tests.unit.cli import test_cli_helpers as legacy


LINE = "\x1b[32m+    value = compute(item, index)  # benign diff line\x1b[0m\n"
PROJECTION = "+    value = compute(item, index)  # benign diff line "


@pytest.mark.parametrize("count", [16, 159, 1000, 1600, 4444, 5000])
def test_dense_benign_projection(count):
    shown = primitives.sanitize_display(LINE * count, max_len=None)
    assert shown == PROJECTION * count
    assert "[REDACTED]" not in shown


@pytest.mark.parametrize("size", [1000, 10000, 100000, 280000])
def test_exact_input_sizes_keep_dense_projection(size):
    count, tail = divmod(size, len(LINE))
    value = LINE * count + "b" * tail
    assert len(value) == size
    assert primitives.sanitize_display(value, max_len=None) == PROJECTION * count + "b" * tail


def test_dense_split_secret_and_retry_in_parallel():
    key = "AK" + "IA" + "A" * 16
    values = [LINE * 1600, LINE * 500 + key[:2] + "\x1b[32m" + key[2:] + LINE * 500] * 3
    expected = [PROJECTION * 1600, "[REDACTED]"] * 3
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(lambda value: primitives.sanitize_display(value, max_len=None), values)) == expected
    assert [primitives.sanitize_display(value, max_len=None) for value in values[:2]] == expected[:2]


def test_width_and_small_exact_window_do_not_compile_graph(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("width lookup or exact interpretation compiled attribution graph")

    primitives._display_attribution_tables.cache_clear()
    primitives._display_attribution_width.cache_clear()
    monkeypatch.setattr("aegis_core.display_attribution.compile_possible", forbidden)
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(lambda _: primitives.sanitize_display("left\x1b[31mright", max_len=None),
                             range(6))) == ["leftright"] * 6
    assert primitives.sanitize_display("left\x1b[31mright", max_len=None) == "leftright"


@pytest.mark.parametrize("limit", [0, 1, 4])
def test_memo_cap_falls_back_to_local_budget_and_retries(limit, monkeypatch):
    monkeypatch.setattr("aegis_core.display_attribution._DFA_STATE_LIMIT", limit)
    monkeypatch.setattr("aegis_core.primitives._DISPLAY_ATTRIBUTION_CEILING", 50000)
    # Keep the window below the ceiling so it reaches the capped DFA before
    # the ordinary NFA fallback exhausts its remaining budget.
    first = "before\x1b]title\x07" + LINE * 100 + "\x1b]title\x07after"
    expected = "before[REDACTED]after"
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(lambda _: primitives.sanitize_display(first, max_len=None), range(3))) == [expected] * 3
    assert primitives.sanitize_display("safe\x1b[31mtext", max_len=None) == "safetext"


def test_memo_member_cap_falls_back_without_changing_proof(monkeypatch):
    monkeypatch.setattr("aegis_core.display_attribution._DFA_UNIT_LIMIT", 1)
    grammar = attribution.compile_possible([re.compile("needle")])
    runs = [(0, 1000, 0, True, None, 0)]
    assert not attribution.may_match_visible(grammar, "z" * 1000, runs, lambda _: True)
    assert attribution.may_match_visible(grammar, "z" * 1000, runs, lambda _: False)


def test_cached_proof_still_refuses_when_hit_budget_is_exhausted():
    remaining = [100]

    def charge(amount):
        if amount > remaining[0]:
            return False
        remaining[0] -= amount
        return True

    grammar = attribution.compile_possible([re.compile("needle")])
    runs = [(0, 1000, 0, True, None, 0)]
    assert attribution.may_match_visible(grammar, "z" * 1000, runs, charge)
    assert remaining == [0]
    assert not attribution.may_match_visible(grammar, "z" * 1000, runs, lambda _: True)


def test_budget_refusal_stays_in_affected_window(monkeypatch):
    monkeypatch.setattr("aegis_core.primitives._DISPLAY_ATTRIBUTION_CEILING", 0)
    value = "before\x1b]title\x07" + LINE * 20 + "\x1b]title\x07after"
    assert primitives.sanitize_display(value, max_len=None) == "before[REDACTED]after"


@pytest.mark.parametrize("pattern", [r"(?<!x)a[bc]{1,2}", r"(?i)(?<![a-z])ab", r"a(?:bc|d){1,3}"])
def test_memo_matches_uncached_optional_and_lookbehind_states(pattern):
    grammar = attribution.compile_possible([re.compile(pattern)])
    for value in ("abc", "xabc", "abcbcd", "ABC", "zzz", "xabc" * 20):
        for visible in (True, False):
            runs = [(i, i + 1, i % 2, visible or i % 3 == 0, None, 0) for i in range(len(value))]
            for start in (0, 1):
                expected = attribution.may_match_visible(grammar, value, runs, lambda _: True,
                                                         start_at=start, memoize=False)
                assert attribution.may_match_visible(grammar, value, runs, lambda _: True,
                                                     start_at=start) == expected


# Sorted display tests with no patch fixture, then the legacy escape corpus.
# A rename, a new test, or a new fixture must update this registry. The floor
# below refuses a parametrize row that disappears without a name change.
REPLAY_FUNCTIONS = (
    "tests.unit.core.test_primitives.test_display_attribution_adjacent_colours_keep_long_context",
    "tests.unit.core.test_primitives.test_display_attribution_budget_is_local_to_retries_and_parallel_calls",
    "tests.unit.core.test_primitives.test_display_attribution_clipped_window_does_not_create_a_left_boundary",
    "tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families",
    "tests.unit.core.test_primitives.test_display_attribution_detection_windows_keep_visible_whitespace",
    "tests.unit.core.test_primitives.test_display_attribution_detection_windows_retry_after_large_gap_in_parallel",
    "tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps",
    "tests.unit.core.test_primitives.test_display_attribution_exhausted_window_does_not_poison_later_window",
    "tests.unit.core.test_primitives.test_display_attribution_fallback_keeps_carried_starts",
    "tests.unit.core.test_primitives.test_display_attribution_fallback_preserves_ordinary_boundary_and_flags",
    "tests.unit.core.test_primitives.test_display_attribution_hidden_only_credential_does_not_mask_visible_context",
    "tests.unit.core.test_primitives.test_display_attribution_long_benign_colour_runs_keep_parity",
    "tests.unit.core.test_primitives.test_display_attribution_masks_overlapping_ordinary_credentials",
    "tests.unit.core.test_primitives.test_display_attribution_overlaps_and_fallback_are_isolated_in_parallel",
    "tests.unit.core.test_primitives.test_display_attribution_preserves_ordinary_left_boundary",
    "tests.unit.core.test_primitives.test_display_attribution_widths_and_unknown_grammars_fail_conservatively",
    "tests.unit.core.test_primitives.test_display_boundaries_are_local_to_parallel_calls_and_retries",
    "tests.unit.core.test_primitives.test_display_boundary_detection_keeps_secrets_split_by_inner_controls_masked",
    "tests.unit.core.test_primitives.test_display_boundary_detection_uses_shared_secret_families",
    "tests.unit.core.test_primitives.test_display_boundary_mask_preserves_legacy_kind_bytes_and_plain_baseline",
    "tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers",
    "tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control",
    "tests.unit.core.test_primitives.test_display_deleted_view_preserves_bel_termination_and_nonsecret_parity",
    "tests.unit.core.test_primitives.test_display_does_not_orphan_value_after_guarding_secret_key_context",
    "tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface",
    "tests.unit.core.test_primitives.test_display_pem_extents_cover_differently_labelled_nested_body",
    "tests.unit.core.test_primitives.test_display_preserves_url_context_and_masks_overlapping_secret_rules",
    "tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header",
    "tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header",
    "tests.unit.core.test_primitives.test_display_provenance_masks_overlaps_inside_an_ordinary_match",
    "tests.unit.core.test_primitives.test_display_provenance_overlaps_and_headers_are_independent_in_threads",
    "tests.unit.core.test_primitives.test_display_reassembled_tokens_use_markers_before_caller_redaction",
    "tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries",
    "tests.unit.core.test_primitives.test_display_rendered_segments_keep_visible_credential_whitespace",
    "tests.unit.core.test_primitives.test_display_rendered_segments_preserve_visible_space_inside_nonsecret",
    "tests.unit.core.test_primitives.test_display_rendered_segments_seal_hidden_token_prefix",
    "tests.unit.core.test_primitives.test_display_rendered_segments_still_join_fully_removed_controls",
    "tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers",
    "tests.unit.core.test_primitives.test_display_renderer_provenance_recovers_consumed_credential_label",
    "tests.unit.core.test_primitives.test_display_restored_union_masks_before_boundary_changes_or_clipping",
    "tests.unit.core.test_primitives.test_display_source_guard_cannot_complete_a_new_credential_or_tear_a_mask",
    "tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace",
    "tests.unit.core.test_primitives.test_display_source_segments_do_not_join_visible_context_through_hidden_payload",
    "tests.unit.core.test_primitives.test_display_source_segments_keep_prefixed_secret_context_detectable",
    "tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings",
    "tests.unit.core.test_primitives.test_display_source_segments_still_mask_visible_secrets_on_both_sides",
    "tests.unit.core.test_primitives.test_display_source_view_accepts_control_only_nonsecret_text",
    "tests.unit.core.test_primitives.test_display_source_view_bounds_repeated_unterminated_pem_work",
    "tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls",
    "tests.unit.core.test_primitives.test_display_source_view_masks_credentials_partly_consumed_by_csi",
    "tests.unit.core.test_primitives.test_display_source_view_masks_only_surviving_characters_and_preserves_context",
    "tests.unit.core.test_primitives.test_display_ten_million_removed_controls_do_not_build_per_control_state",
    "tests.unit.core.test_primitives.test_display_unions_canonical_and_source_only_masks",
    "tests.unit.cli.test_cli_helpers.test_display_matches_legacy_output_for_supported_escape_corpus",
)
# Explicit round-1 cases, refreshed for round 1d after #667. Each row is the stable id, the original test, and the
# arguments that test received. The replay is built from CORPUS_CASES. The
# original tests bind their parameters from this same table after definition.
# original_call_cases reads those parametrizations, and shared_table_errors
# compares ids and argument digests with this table in both directions.
# Argument text is split
# into short pieces so the source does not hold a contiguous token.
# ROUND1_CASE_BASELINE is the recorded id, test name, and argument digest for
# the 1,430 current cases (the original 1,101 plus 329 proposal cases).
ROUND1_CASE_BASELINE = (
    ('nfa-test_display_attribution_adjacent_colours_keep_long_context-0', 'tests.unit.core.test_primitives.test_display_attribution_adjacent_colours_keep_long_context', '44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a'),
    ('nfa-test_display_attribution_budget_is_local_to_retries_and_parallel_calls-0', 'tests.unit.core.test_primitives.test_display_attribution_budget_is_local_to_retries_and_parallel_calls', '44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a'),
    ('nfa-test_display_attribution_clipped_window_does_not_create_a_left_boundary-0', 'tests.unit.core.test_primitives.test_display_attribution_clipped_window_does_not_create_a_left_boundary', '44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a'),
    ('nfa-test_display_attribution_covers_shared_rule_families-0', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', '597d826a68a9fcf4cc18dc8c6505a6f8e1c5edc0e319479e6501833c32444cfd'),
    ('nfa-test_display_attribution_covers_shared_rule_families-1', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', '1d80495cb249bff16a6fb9b1f02adebb33d3070649e3a01dc44e2aac3790291f'),
    ('nfa-test_display_attribution_covers_shared_rule_families-2', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', '142483f529d04ffe33a6081fd2c3ac446a41837c4cc53c59150df9be8f0d7078'),
    ('nfa-test_display_attribution_covers_shared_rule_families-3', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', '4a2cebfa36a0dbbc5e0704b238f7a5b9e6948f245f6339f4d9bea931d94024a7'),
    ('nfa-test_display_attribution_covers_shared_rule_families-4', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', '00a9339683b6833aa9359705efa6c71f7e10dfc71bc3d821151e3ddb159d3316'),
    ('nfa-test_display_attribution_covers_shared_rule_families-5', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', 'ce8d31ae0700117291c211a0f2d8a51964aab55df746b2ccd72029382dd289b5'),
    ('nfa-test_display_attribution_covers_shared_rule_families-6', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', '3fc088aedce9f9349aa5a99124eca7797cb78f3661a8465c9a1e20d194933600'),
    ('nfa-test_display_attribution_covers_shared_rule_families-7', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', '1b5a17e93f3b66c6653df0e5e49416e690722dd44443b42364bfdf89ce7b4716'),
    ('nfa-test_display_attribution_covers_shared_rule_families-8', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', '64033499a434a9c1b66f4e3a4f4ebb4eaff47d6c7a6f948ede0b8c1dd992d1d1'),
    ('nfa-test_display_attribution_covers_shared_rule_families-9', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', '882fc17b6c9123cfe0b739bb9920f45b359d59bc0447d2dc9d110253ac8dd18d'),
    ('nfa-test_display_attribution_covers_shared_rule_families-10', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', '21d0c58d41b52e0e1e447d36204fff78c2a89caea3d01bf322c2f486eed7d3bc'),
    ('nfa-test_display_attribution_covers_shared_rule_families-11', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', '03e636031c1ef092849883fad5a77f76ac4823295cf97fb6ab344a6058b58956'),
    ('nfa-test_display_attribution_covers_shared_rule_families-12', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', '9dbe935013bddb7bb9b7a53c1a6ba6feac65bbf9513c292ccd65a59cd2eb299d'),
    ('nfa-test_display_attribution_covers_shared_rule_families-13', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', 'e2b3bf9d7ea219535d087aadf1c1eedf35c141f9ce6c512c9e63795a58dbb81c'),
    ('nfa-test_display_attribution_covers_shared_rule_families-14', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', '17d1756765244fd528c2fb398fa4572d26dfe1fcc106358acbf6db640b60bfe3'),
    ('nfa-test_display_attribution_covers_shared_rule_families-15', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', 'c06e46db66c4bd5f82f309da850a3039cdad43a92dcaf585b8f205ad1ae07946'),
    ('nfa-test_display_attribution_covers_shared_rule_families-16', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', '7e19639fb2469647347e3c875a11c25e00f06bff72b1fae13a241b12ce996229'),
    ('nfa-test_display_attribution_covers_shared_rule_families-17', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', '4883de912a727fa7207a0c9755afdaf193e37b7290a256a35a81f309b109ea4b'),
    ('nfa-test_display_attribution_covers_shared_rule_families-18', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', 'b244602c4fe1bfa4803cf33cad2c7e8f091bd30b1df9b3288d4cd8913cc83748'),
    ('nfa-test_display_attribution_covers_shared_rule_families-19', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', '26876fd9a47ddbaa5ba069979c8ca14784fd054d372391c5ca6e722137dbdf71'),
    ('nfa-test_display_attribution_covers_shared_rule_families-20', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', '6d04d3c2598cd06dbfe06fa19df5eea27a51eee2d5f68f52e80261db9fa03ed5'),
    ('nfa-test_display_attribution_covers_shared_rule_families-21', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', 'cf0d462dab5ca3996bbc3b95258537d3c7cae3ac910a03ce84c6e5d203f55237'),
    ('nfa-test_display_attribution_covers_shared_rule_families-22', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', 'b2181b19c436f2a0ff51ab749ba28b3952f70e3062587ca13c435cd84c0ae220'),
    ('nfa-test_display_attribution_covers_shared_rule_families-23', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', '24f160fb24c6733c3963f48ba1e6e36b979525eba759128a226c656e274e077b'),
    ('nfa-test_display_attribution_covers_shared_rule_families-24', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', 'c29d986490c0b5f7664afe2bb460ff64389c9188ac865a5d6170de40a4e59616'),
    ('nfa-test_display_attribution_covers_shared_rule_families-25', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', 'c8caa97f8b993158d6f69220352c807e008e7013b584a2dd5584450a9dd8875f'),
    ('nfa-test_display_attribution_covers_shared_rule_families-26', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', '16ccacfc6549eb0591f1dabeda5a2943eac3d9f8e4434556a47273190dd6706e'),
    ('nfa-test_display_attribution_covers_shared_rule_families-27', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', 'bd20688c52bfbd577ad36a2b153f37a4e48f042c37cb373e2ea486743b374c85'),
    ('nfa-test_display_attribution_covers_shared_rule_families-28', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', '2fab66b35bdb1211d0f9f3b1df120f2171b2fe2551d4085a2292fe9e8d5ef750'),
    ('nfa-test_display_attribution_covers_shared_rule_families-29', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', 'b0c96d30980058b78938da619788fda9fab49363a5ad301c0d48cb5babea000f'),
    ('nfa-test_display_attribution_covers_shared_rule_families-30', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', 'ba626903df82fdcfd9bfa1915535d66f1f04fa95ad16fae07b52c75f72ab9447'),
    ('nfa-test_display_attribution_covers_shared_rule_families-31', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', 'f7e897d9cdeed278579584ef31c497c0672ff9e04f3a6a5ff844d3421a08a184'),
    ('nfa-test_display_attribution_covers_shared_rule_families-32', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', '003f3d36e766de679da646529fb5bb86ea096b26792566bd85ae4ee5898986bc'),
    ('nfa-test_display_attribution_covers_shared_rule_families-33', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', 'd2d0bada8b4952623ba27c1348227f5a20920128df24eb083135b86a080e00cd'),
    ('nfa-test_display_attribution_covers_shared_rule_families-34', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', 'a2656f3a3fa4da01320c6bfd52c1b4ed3e723a1e85e81599f71b6c20b7dba9d5'),
    ('nfa-test_display_attribution_covers_shared_rule_families-35', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', 'cb2ba62fbb6c82dcb1d23a58fb16a43c4fdaea21214e268a7f9256ac687ddfab'),
    ('nfa-test_display_attribution_covers_shared_rule_families-36', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', '9bd13371a18a7d19cdb34721ce4fa2697d90f03bbf05e2689e6cff96cee7c227'),
    ('nfa-test_display_attribution_covers_shared_rule_families-37', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', 'ee1fd61532c04f898c35804133705746767226f09bd92810aa5178c41f726268'),
    ('nfa-test_display_attribution_covers_shared_rule_families-38', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', '5e19b44234fc90f63bd6d253371b59aa534bc43fe4df299aa54e7c6cef5be3e4'),
    ('nfa-test_display_attribution_covers_shared_rule_families-39', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', '17900948407a64c6f4954e366ee37fea28f2502204e0dae392224da90055893f'),
    ('nfa-test_display_attribution_covers_shared_rule_families-40', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', '1395308f1574e04226c9852fcd27a1be5b854b7062c3e75a20553d1b34c27169'),
    ('nfa-test_display_attribution_covers_shared_rule_families-41', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', '855e2e12fb5960e9c3b34e1e7a569eb0a9a1e5669acc72333b3fc5ba720604f1'),
    ('nfa-test_display_attribution_covers_shared_rule_families-42', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', 'f59e3ad115457a240ca89daa9c7cf0382b7e7430c1a68ec63fa1bfa2b842630a'),
    ('nfa-test_display_attribution_covers_shared_rule_families-43', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', '50a2812a285eda22e1c6cbfe70ba528d2d3abf5337f087e9c35bbeea56979a47'),
    ('nfa-test_display_attribution_covers_shared_rule_families-44', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', 'e22b299a9d20f4f0af1f4abcb3338de89e293322a411b87508d847dbe2f226e6'),
    ('nfa-test_display_attribution_covers_shared_rule_families-45', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', '67c854ae3432c40108a99e17c18839ea83af77e17d53186c69ee7584122da8c5'),
    ('nfa-test_display_attribution_covers_shared_rule_families-46', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', 'ba1237163fcfa671dfa789f2958e3544cf203999c8ac18f5731a3828d15acccd'),
    ('nfa-test_display_attribution_covers_shared_rule_families-47', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', '0c271a0393cf6420a8abc02abd95dd1af62110f1ead028b6b9433360b2909e6f'),
    ('nfa-test_display_attribution_covers_shared_rule_families-48', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', '7d69c5d023937b4687135508f271eac446880593a54c2049100502151621b06f'),
    ('nfa-test_display_attribution_covers_shared_rule_families-49', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', 'a0d3859dab93b54042ba5f9ad717a67503dfebc713b465fec7b8d63a276b541c'),
    ('nfa-test_display_attribution_covers_shared_rule_families-50', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', '57f920471e2d650c4e75c06b7b0e82457750603a0d707696548376eee0ca180d'),
    ('nfa-test_display_attribution_covers_shared_rule_families-51', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', 'cebec9621d745f1eb66e2b84b6ac69288d928ea2a798c06935c97f29d0120bd0'),
    ('nfa-test_display_attribution_covers_shared_rule_families-52', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', 'cb4a260c0055701553fe63b6478b2f4a877485539842bc71d477e6baf0106b45'),
    ('nfa-test_display_attribution_covers_shared_rule_families-53', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', '9d1bf1932a3f0b57c41bd56b8a6059f99815f194aa06190004a22bb239b5e228'),
    ('nfa-test_display_attribution_covers_shared_rule_families-54', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', '4d8ce3d2cbf18cf4c9116a23086b179e4ecf39e48519a410eabecabd7e971b52'),
    ('nfa-test_display_attribution_covers_shared_rule_families-55', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', 'c84cbe1e23deff29316b959382d912a6cdde5b7324403c85d9b5f3fd8ed5a086'),
    ('nfa-test_display_attribution_covers_shared_rule_families-56', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', 'e1792f2dfbcc152558e6628fd9a4ad9c49450a3825c666e83a3e2e41eaddeefa'),
    ('nfa-test_display_attribution_covers_shared_rule_families-57', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', '709c0b828902f1d5581a44f7dafe0ae76654d67cc044e993ac9bbe8b4e8f8b6b'),
    ('nfa-test_display_attribution_covers_shared_rule_families-58', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', 'd341ce8bc8c5f21f2cb246bf60638534fa0e113a07cd9ffa3bd8720d939aca9a'),
    ('nfa-test_display_attribution_covers_shared_rule_families-59', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', 'c8bdca67fde872417f50cadee6cd95a1c887bd3882e7edc88f1ca96efe86196c'),
    ('nfa-test_display_attribution_covers_shared_rule_families-60', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', 'fc7f7f041530230e6a69f566a1e9a74eb580f0ee052881ae332c8f2b8c7b4e9f'),
    ('nfa-test_display_attribution_covers_shared_rule_families-61', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', '4eb1d2f8e068f0a0964cafdaddeb3e754f201d156e99262ce968007ffd748b59'),
    ('nfa-test_display_attribution_covers_shared_rule_families-62', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', 'f3f7a46819536c26589bae4f42509a8e3c2a8d68b13a44954590f201a9ea1964'),
    ('nfa-test_display_attribution_covers_shared_rule_families-63', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', '410859d5ef3233709aa5177df9621f416115624de12fac374493c59616d1e7c9'),
    ('nfa-test_display_attribution_detection_windows_keep_visible_whitespace-0', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_keep_visible_whitespace', '44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a'),
    ('nfa-test_display_attribution_detection_windows_retry_after_large_gap_in_parallel-0', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_retry_after_large_gap_in_parallel', '44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a'),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-0', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', 'b851cfc44104a92fabec4495a41dab5633a86162da8ad4237f946a932fe68842'),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-1', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', 'c4b9d770e4299d6a170414fd2633de952ba47dcf73b0ebf0ccd20edc49970dcb'),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-2', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', '17000cd6af397c38c70a59c0347c05033e6a71c5b8e031cab876ace163cabc30'),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-3', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', '192b10aab932807fbc59ef1973cc6e0114f13574d71d073257a175b827ac96c3'),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-4', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', '7e6a0a097a36473609fba1e73b400eef72521dd9e951c48ee494ee559eb694fa'),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-5', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', '62ace92bb51ceeb5f025af2e757bb36ebc8c068609c63c0698db9a6b4f8ba359'),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-6', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', '795ae1130b73b3fc12e3d0fa7bd1bdbcbac61b6517ef01669bcf8c523460b058'),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-7', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', '8b442e0fc41125acbd94c27e089ac83fd0ebd633d60a2e70c7ffd0a4fac8d32a'),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-8', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', '085baa4f6ab0212984cbdaa79274b07c546320a1ab9f0b740887d5e0319c4bdf'),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-9', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', '8a86596edbc0ea6e0117caca08a5294514d87b55204eaccc1fa88df37bd9e267'),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-10', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', '2a246d54f0f7b5787b97a1735927f3662dd336b5788743becea581b53da065e3'),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-11', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', 'ad21e51bd45135aaa1ce60c4395a7cc5ee3ed3eeb4ee67e81288cf76de3c79dc'),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-12', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', '0983908fabec6e20249140d494d35fbdab3eddc57f7998e454a63a0ef9ebcdd6'),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-13', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', 'f011b1e352e92a5a056d788cdea2a834d540a7e4b37a381584836323f31b97d7'),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-14', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', 'e95b5a16acaadcd47cc2b62c0b766707ffad2a49c24835c9d041bb8bd9115d39'),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-15', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', 'a27e0dc306966833ce71efd5eb48b8e598142ddf87ae34cb423ac5ec6f1ffcc1'),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-16', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', '28d4c24082755c5a5b2fb5fe576c8f2f86448be1d8dfb611bc2b7dc6ec6d1aeb'),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-17', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', 'f8dc65c70b6234b0e0583ea2cecdf3d3d16cad985c2a47765bba2735efc9ca90'),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-18', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', '8f5ab0bf3cc94579891a01caff7fa681d73713b926925f3c563bc28151853fe4'),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-19', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', 'e4620cbe03d670d1edaef0afca5b97b6cbd5f9e901537a22a899d25fba847828'),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-20', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', 'f19709c0096e217a1583ccecc0771f0a91834949fad028c5e5b48a4099569647'),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-21', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', '1340988e5e90e536113e72eef8d5cbd92e414033788d75f0c89cd8e3594dd018'),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-22', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', '88b1964dbe268588ed3ebcb5f906279695ad3c18953341f7d33f2da06c4eac73'),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-23', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', '9eeaed7c1cc7564f7485e3e0bb42cf1fe86689db12d5cd286d474fa63e1d51c0'),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-24', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', '905ddec5abd9946151797f3a7d0a8a184eb3e38a3d428e4c8227d82ee782118e'),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-25', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', '720e17777660e31540b67361bb331723b163c7e6e1bee554dfea2b16065769ff'),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-26', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', '4f4fc282f65c7f0c4b908043ab230f3a959e75749cd213b2230803b30384803a'),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-27', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', '9cb9078bb427254621a94633049ec64353fcc3ea3729f2a50bc78107db1022da'),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-28', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', '7050ce910ed3bab33691be42e68bba1035b712d583054978b928e110cc11d56f'),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-29', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', '2abff1b1ee7a691194d23694323e196e36f3558e99d6dfcccf76c441273eba27'),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-30', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', 'e507ac8b6f3ec411ac774c16f20b2ead76a2c88f9871001a60baf8c750c2099f'),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-31', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', '1d185cc52d6e25208fce717d991b82ec9168f4f6865202598eec3f621ff2b23b'),
    ('nfa-test_display_attribution_exhausted_window_does_not_poison_later_window-0', 'tests.unit.core.test_primitives.test_display_attribution_exhausted_window_does_not_poison_later_window', '44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a'),
    ('nfa-test_display_attribution_fallback_keeps_carried_starts-0', 'tests.unit.core.test_primitives.test_display_attribution_fallback_keeps_carried_starts', '2ff5ac077c26be74c0dcf01ce66cb8134d4300d055390986ccb7da388733bc57'),
    ('nfa-test_display_attribution_fallback_keeps_carried_starts-1', 'tests.unit.core.test_primitives.test_display_attribution_fallback_keeps_carried_starts', 'f2b21dcbcac2a5b21ba08bbafdf6ec0e364745d4785f3f6504d30a7dc768c170'),
    ('nfa-test_display_attribution_fallback_keeps_carried_starts-2', 'tests.unit.core.test_primitives.test_display_attribution_fallback_keeps_carried_starts', 'dd53b0dbd430817b1b05332ac9ae8b6012ada9120c441ddfbddc2694c4ab38d2'),
    ('nfa-test_display_attribution_fallback_keeps_carried_starts-3', 'tests.unit.core.test_primitives.test_display_attribution_fallback_keeps_carried_starts', '4033eb75823da5798536f8a38c6a8cd22ab836cb8d2d4c2e82984990ddc1f3b1'),
    ('nfa-test_display_attribution_fallback_preserves_ordinary_boundary_and_flags-0', 'tests.unit.core.test_primitives.test_display_attribution_fallback_preserves_ordinary_boundary_and_flags', 'a9f48afd2f8ed467effe443d59ecb3e203ed4f9c36a950f4e650b0bda8dfb4f2'),
    ('nfa-test_display_attribution_fallback_preserves_ordinary_boundary_and_flags-1', 'tests.unit.core.test_primitives.test_display_attribution_fallback_preserves_ordinary_boundary_and_flags', '4f486cc9f830b1018ab56e0a39bfaab20245bb6a851cb0fa31e5305c25e0a212'),
    ('nfa-test_display_attribution_fallback_preserves_ordinary_boundary_and_flags-2', 'tests.unit.core.test_primitives.test_display_attribution_fallback_preserves_ordinary_boundary_and_flags', '4c4e2ed8f6cfb69f0db65ac7de6831f0f71070dab086aa68499b169beca7b20e'),
    ('nfa-test_display_attribution_fallback_preserves_ordinary_boundary_and_flags-3', 'tests.unit.core.test_primitives.test_display_attribution_fallback_preserves_ordinary_boundary_and_flags', '2e4c98ef2c22d40d129c08de1a9e75694dc8de4f5a154bfd13c4012edacbad58'),
    ('nfa-test_display_attribution_fallback_preserves_ordinary_boundary_and_flags-4', 'tests.unit.core.test_primitives.test_display_attribution_fallback_preserves_ordinary_boundary_and_flags', '05aa35db5f00dc278784201e54fb97b897c6294e348eb0643cf42b36eca92b73'),
    ('nfa-test_display_attribution_fallback_preserves_ordinary_boundary_and_flags-5', 'tests.unit.core.test_primitives.test_display_attribution_fallback_preserves_ordinary_boundary_and_flags', '42ef099385144a0b152cf89261d1c89598b8fac983a7794b0c701f43844d14b0'),
    ('nfa-test_display_attribution_fallback_preserves_ordinary_boundary_and_flags-6', 'tests.unit.core.test_primitives.test_display_attribution_fallback_preserves_ordinary_boundary_and_flags', 'ae857a4d158bc8d19fec44261a8b0361f99dc91ceb8c2b4f11a729f0f0025c7c'),
    ('nfa-test_display_attribution_fallback_preserves_ordinary_boundary_and_flags-7', 'tests.unit.core.test_primitives.test_display_attribution_fallback_preserves_ordinary_boundary_and_flags', 'e14c6adaeecaaade5f0510f152beae9895d0e65839c47a1c798ab74d9999a09f'),
    ('nfa-test_display_attribution_hidden_only_credential_does_not_mask_visible_context-0', 'tests.unit.core.test_primitives.test_display_attribution_hidden_only_credential_does_not_mask_visible_context', '44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a'),
    ('nfa-test_display_attribution_long_benign_colour_runs_keep_parity-0', 'tests.unit.core.test_primitives.test_display_attribution_long_benign_colour_runs_keep_parity', '6aea6dfe6561984cdc5c54ead84d47d2cf29e48253ae282aef237404adad4661'),
    ('nfa-test_display_attribution_long_benign_colour_runs_keep_parity-1', 'tests.unit.core.test_primitives.test_display_attribution_long_benign_colour_runs_keep_parity', '0c07187ea6d064441225b3cba26a7b1e8bc702fcf332b457dae8e26892ba68a6'),
    ('nfa-test_display_attribution_long_benign_colour_runs_keep_parity-2', 'tests.unit.core.test_primitives.test_display_attribution_long_benign_colour_runs_keep_parity', '1fb6f6be8607ab15c04198cba240a52c2ae4524e5d0d79068813f1972f29054c'),
    ('nfa-test_display_attribution_masks_overlapping_ordinary_credentials-0', 'tests.unit.core.test_primitives.test_display_attribution_masks_overlapping_ordinary_credentials', 'b6a15753c87419f22e37ed40a96b96cf33b4880685cf19ff39db44db1af69297'),
    ('nfa-test_display_attribution_masks_overlapping_ordinary_credentials-1', 'tests.unit.core.test_primitives.test_display_attribution_masks_overlapping_ordinary_credentials', '518d83290678e0b489779a0bc3deb1b42aa0099cec8ea8d89619b76a47f8eb18'),
    ('nfa-test_display_attribution_masks_overlapping_ordinary_credentials-2', 'tests.unit.core.test_primitives.test_display_attribution_masks_overlapping_ordinary_credentials', 'de2491581f431aba65897d67b191996e09bb5dbdf85de1058caeb7885933860b'),
    ('nfa-test_display_attribution_masks_overlapping_ordinary_credentials-3', 'tests.unit.core.test_primitives.test_display_attribution_masks_overlapping_ordinary_credentials', 'f5caaaa2be7c891a716e6ec032c9989b21ceee21b828d4d6ab593cefa25d7c13'),
    ('nfa-test_display_attribution_masks_overlapping_ordinary_credentials-4', 'tests.unit.core.test_primitives.test_display_attribution_masks_overlapping_ordinary_credentials', 'e58e651d283e0bab7fbfab3b56dd4038763815e423f1fb83086b3d893cc30612'),
    ('nfa-test_display_attribution_masks_overlapping_ordinary_credentials-5', 'tests.unit.core.test_primitives.test_display_attribution_masks_overlapping_ordinary_credentials', '61e6914c3aa0596b4415a753e3a967d1b9b6a47220686ff44eb4d8240fd9e424'),
    ('nfa-test_display_attribution_masks_overlapping_ordinary_credentials-6', 'tests.unit.core.test_primitives.test_display_attribution_masks_overlapping_ordinary_credentials', 'b47b039088229dfa52d867c5211ae003aba9e2894b9d1f87b4385b676d85915f'),
    ('nfa-test_display_attribution_masks_overlapping_ordinary_credentials-7', 'tests.unit.core.test_primitives.test_display_attribution_masks_overlapping_ordinary_credentials', 'b1ebcb000eb5d71c7949fdbc5f7cc5f09168700ec768cb1763bc0bd11ca28a12'),
    ('nfa-test_display_attribution_overlaps_and_fallback_are_isolated_in_parallel-0', 'tests.unit.core.test_primitives.test_display_attribution_overlaps_and_fallback_are_isolated_in_parallel', '44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a'),
    ('nfa-test_display_attribution_preserves_ordinary_left_boundary-0', 'tests.unit.core.test_primitives.test_display_attribution_preserves_ordinary_left_boundary', 'e8c7883b08b67b1d8b5469785d232dc4fe1e679fb0766f8e00bd72a10d49d7db'),
    ('nfa-test_display_attribution_preserves_ordinary_left_boundary-1', 'tests.unit.core.test_primitives.test_display_attribution_preserves_ordinary_left_boundary', 'ee7e6b3714eb68ae0b1fa92bedc1144d767a3fc04d7de67fa3f8b4437e97419c'),
    ('nfa-test_display_attribution_widths_and_unknown_grammars_fail_conservatively-0', 'tests.unit.core.test_primitives.test_display_attribution_widths_and_unknown_grammars_fail_conservatively', '44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a'),
    ('nfa-test_display_boundaries_are_local_to_parallel_calls_and_retries-0', 'tests.unit.core.test_primitives.test_display_boundaries_are_local_to_parallel_calls_and_retries', '44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a'),
    ('nfa-test_display_boundary_detection_keeps_secrets_split_by_inner_controls_masked-0', 'tests.unit.core.test_primitives.test_display_boundary_detection_keeps_secrets_split_by_inner_controls_masked', '44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a'),
    ('nfa-test_display_boundary_detection_uses_shared_secret_families-0', 'tests.unit.core.test_primitives.test_display_boundary_detection_uses_shared_secret_families', 'aaa88f30b90ebcdbc42ced53a1f1e285298c3fb3ccd4dac9d473633e1bcf07a3'),
    ('nfa-test_display_boundary_detection_uses_shared_secret_families-1', 'tests.unit.core.test_primitives.test_display_boundary_detection_uses_shared_secret_families', '1741438b4c4958d94916ecf336beec69444ded29bf77571819426340e65770b3'),
    ('nfa-test_display_boundary_detection_uses_shared_secret_families-2', 'tests.unit.core.test_primitives.test_display_boundary_detection_uses_shared_secret_families', '00b54b9b8b8b743072d081d12a2ec9d3640a21c76d78f82402ed111347c1a8cd'),
    ('nfa-test_display_boundary_detection_uses_shared_secret_families-3', 'tests.unit.core.test_primitives.test_display_boundary_detection_uses_shared_secret_families', '522c5114472c4c8f0f0dad93b77aa30fb572f26ab7f529d3afd00b810b9c97f0'),
    ('nfa-test_display_boundary_detection_uses_shared_secret_families-4', 'tests.unit.core.test_primitives.test_display_boundary_detection_uses_shared_secret_families', '3a90ff19982956dd0ccdfc81d6df68dea54e6934ce05f4a288b204184373f4d8'),
    ('nfa-test_display_boundary_detection_uses_shared_secret_families-5', 'tests.unit.core.test_primitives.test_display_boundary_detection_uses_shared_secret_families', '9dd5380e18fd30ff9aa9741bce822b3d5440f38ae19acd62bf77b4b1366e849c'),
    ('nfa-test_display_boundary_detection_uses_shared_secret_families-6', 'tests.unit.core.test_primitives.test_display_boundary_detection_uses_shared_secret_families', '62b5a2755b6beeac9cd915de09dca71476d81c455152299bc74707f268219cef'),
    ('nfa-test_display_boundary_mask_preserves_legacy_kind_bytes_and_plain_baseline-0', 'tests.unit.core.test_primitives.test_display_boundary_mask_preserves_legacy_kind_bytes_and_plain_baseline', '44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a'),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-0', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', '2d0583ce5e9146d9358a66b17a32d8999b01c1eb738160166f64b972fdf493d1'),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-1', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', 'b32ab4520c6409de6c459e015ec1b335e7e7a713c0cbb8949def227d311fbdfa'),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-2', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', 'd651d352ebcaa8e93f529de7c5760e638b823068fc52c4f4f3d4fe6e95f8aa9c'),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-3', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', 'a4079ca937ec35a51af7f1c70e5743b77a6aa991247525fecc6e35d7265627c3'),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-4', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', 'ed10eded3be0e012d3b457be5d7d0efe0a0226cd0ab4d17cb61c36dc97d900ba'),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-5', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', '12379b8c700196d4b84f682bc175efb06fcd0a88e3111121b7d7dab06485daff'),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-6', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', 'b308cfbc5d5219663ddbc79c21e233a0b1081572514d01393cb5a3ca01651674'),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-7', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', 'a2e19daf6b7231a59aadf18b966ab7f6590bc2adfb62697c2698059f2342e5c3'),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-8', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', 'c7f7a23c653420e88c0d7d1ef16d85e0ba3ae346d0243008a208a7a2256a07da'),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-9', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', '9da05b73e5da7e40a28a53d7fcb1bb27826b1746e550eba50d53b61017ca04ae'),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-10', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', '3fdbd848f2361b081a6c53913a83f5a7221afacca48635be7726f3f5bc7b37ce'),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-11', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', '588a1bfab0105b6fb01549f7f02b9b4ec7121f70c8e442aa340ce9c25761cf2e'),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-12', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', '99f79ba43ffbc54f6af720ca79e86d9292aaa652c4fb73c9d0b96c4642d13012'),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-13', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', 'db11fb0c2b1beef23f82e7483654470abdb1cd6f97e3326b072ae311f2a2c070'),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-14', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', '8f8a1561b3432c1af2b28c93a81e10e78b07b28e1fa418acef091f4ad766351e'),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-15', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', '070bba202db01f886a61bfb063b421364ce07277a9d27579cd46d25ad67cbefd'),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-16', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', 'e8688d1994bf22cce5be742d82ee4879a5ea92e346aa68df92c25585c5c65e69'),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-17', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', '04cc728ce5a631b3f2a8d38f928d4d0cab5d02dd276e99f252edfaf9462cc8ee'),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-18', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', '47432e9ecf25e9018a54c9575fa57b4f3553ab30a66203cfb15b3c8801134c0f'),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-19', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', 'eaa391caab4b9a5b043247e67aaba6f426b69f81744063b6da51ded8c25266c8'),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-20', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', '4ef1a51ff3e7c8779f3d46bbf763208148578ad4c3429d8133cc3d03cb49f9e1'),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-21', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', 'bc2ebc1a41d3997435f7335908b14945cbcab02584315e0546e4875153e21224'),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-22', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', '414f8a9c186d2245c0d3cd062d7e4d20eb045144c475cc694b0bf9211ca3f3c7'),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-23', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', 'b8bd67717bd62ccf210af80d498d684dbd60a0eeec5e49c36eb8c4dacc887116'),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-24', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', '42c7c56e7c04125c4e9bdb6f5206699836d1149475d9aee85e42c0844829cfc5'),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-25', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', 'c4ab37dd08d036066aa547999fd8490ebbc6519591ce76af8a3fc307c597cdea'),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-26', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', 'f5753effdadb162f35a59c56a01c3d58644988005937b8c74896a673f4b72e55'),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-27', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', '7a6b77839c50b89d9b7705cf49ecda185dd9a51aa750d1263f148540cc3f7ef1'),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-28', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', '11b497df06ac6bb9e9e6a3fc7e6c629379809a3a93eb7d431ac94e4d101c0ee2'),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-29', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', 'a49bf2c232d28efb7f79c7d39a85f09327bc8a3bc850342a5d3472cd8ba8a474'),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-30', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', 'e5ca37e845c7b29ebe190900bdab6bc72b168b3118e371b0ae0fb3563a784159'),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-31', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', '63d26d216866b89c6f867208dc2515ec2d6224ae2942447b7e2338cfb5fcdbdb'),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-32', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', '54baedea4313cd8a533eb60f4cd95a2aa7ccab208f8e3b2ef5a4224617d55edc'),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-33', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', 'd85632a61d95e3596a4c16cac02fc498d67765e9896ab95eff16aa3fba9cda4f'),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-34', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', 'a5565f1fcfeecf8987fd80e6d35aeee94b91ed730e4a730291a2ff52388779ce'),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-35', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', 'a1578e15e73dc8f9648ad06b7c95cd09a35c5b9bc61af1f47904771785ed6b01'),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-36', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', '171d2560b52a2f0caacd3ad954cd521ac9cc8391d33d2b7039b2720f0a7dcdbb'),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-37', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', '02ee9ce6532727b7b19ae513ed53f042004a4df37b0fe100e79e16f6666a95c1'),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-38', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', '0bf4e901dc59b9f4e81c42d18607e35ec3e7655a3c9821a9aa312e8548613ba6'),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-39', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', '9699c73c0f9e1ab0f355ec58dac4f991763005b67dc50315c285f5496d53a277'),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-40', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', 'eaaab007180f6b5ba963974942e285c852ed14bcf3ceb16caaf81135939e18c1'),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-41', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', '18627fdd5e2f327f26a22435f654fac13bc410a46e03873df2926da28b7ac483'),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-42', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', '0119d65d73742b53ca980d86948a311a994ae61cfd5b424d9bc81117be58eed0'),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-43', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', '1ae2771ec39d1d30a5ab8bdd5a120eb43f620d1a249025794d3055690f381b2c'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-0', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', '2abc1db24951639002b6bf8cae40d42821a0557b813532e5e73f302c3608edd8'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-1', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', 'a3e70206991c00c889fa9149617e8e16e28af8e593346a32338f3a5184149ff1'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-2', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', 'cdefde271a4a1423dd219ff2e0865a01caf48285ae1e6725fc458efc187914b3'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-3', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', 'faea8d6da29a33aba06b5b5eca6a8ab67cda2b56b540cea69f89ef13c5119bdc'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-4', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', 'a29c3011e02a424eb36467bb25df5b834cafecf7306c085477991a389f676db9'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-5', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', '0e794c4c1949499258f63c267670a296bf8e95a9ecbbda03aff5b84906ce0046'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-6', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', '7389bdc9e05de4dde9ca3caba0a35bd4a3d4a3954e5f621f1e623a5b9c559ec4'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-7', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', 'c288537f712893e9834dc354e37ed54b0a2e340839e601faa43a73a8755cee61'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-8', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', '3af08cda3863936258ab74900a30633ddb7a427730b0f730596a23829fa2145d'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-9', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', '10661e2d68012b507fb16aea319438d864eb0821c326c91d1e72d22fc65752df'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-10', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', 'da207ca0d97afeb385aa09a6b398c0e13b849371c0d5429e34dfa880a8e7c3d0'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-11', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', '37c4a67ec429ad79664cc543fe5fcf52c9601c5cf5825d7c3b41a445167786cf'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-12', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', '3a85ea0a2700d210cdd1c06b65264b64e92f98706084e100d176f6ca3f4dee35'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-13', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', '383f93c2a3c6c65fed69332c0d1152530dbfe2faf3f7db29bc0c2e150bd9d03e'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-14', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', '10ba11fb5ff32b335278602c8399e678d1adbb246e87962fa357a0d4b51724ec'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-15', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', '10baf636465b04a06392cbf701afd75db170bc462fced8d97e0bebad82a08bd7'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-16', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', 'b032f12edf45c7bbd1510ab7418781ef91bf99baf03c9874e6d0da3e06d8c175'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-17', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', '4233321a9376047dddadb1506ab08c36b825aba2af714d3af531fb2f100f0c6a'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-18', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', 'a0414786d1f56574b4362c5a705c0c9344bc2bda83e254bfb37c99434854476c'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-19', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', '459f17b131aed54ee3542f61b5de7ce97a8eda8e390097420dd2422b8a093e0f'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-20', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', 'e586add77831b5efba886d46921b7700521728682a67ad878a0c2ff0deef1e1a'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-21', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', '48151cfd3fea9160f094d3675bcfd10db1aecb98b3d343b1d2e7467dd7acd9e6'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-22', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', '185c5208e917ec21a8067bd50f17ba5b66b058a92e7f241e1579b6869de40192'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-23', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', 'e022a7b0eea1e83c67e6ba874a2b27ab1588614ac4e860a96638683576007362'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-24', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', '8a247d7133f163166da392cd700d84f316fb075320ac94a8946153e599aed30f'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-25', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', 'ade7ddc57c01d0ca5dc16aa689f2d156459904cc2fdffb41bd1af3bb1c283d18'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-26', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', '51595849ddabb90d730a55adf42be73d98342db7c5ce43659ae0281da958430e'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-27', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', '5c9c09309dd6f0fe39649ea6f42acdf68ca61f717a37a0cb9d7bb1c7fab9483c'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-28', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', '5c08bf35b0b0a1ac09469986237c8ccda0c8796f77c9a74c515d6adbe59ca840'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-29', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', '32fa9daeb2da10ccad488b7bbb567bf29aa69cdf25c638fee92c45441d0cc2fe'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-30', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', 'fd86e22df3aca6bf2249598abf3030a962d874a0475b30a54c0c4119703c641b'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-31', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', '6bf2cadea87baab53a2e73de48530f1c3afbdd8e8ed910dbafae8ed42176d318'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-32', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', '9312a7b8104e75d1511fd66cb89430bf2d370bde93324b55272b12cf8e2f1682'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-33', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', 'a3498446cbc3ee8331b01196b187c3b2342323f14d509b0ecd9dcc5552546902'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-34', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', '2a238f0aca7e5191a3d41bf57b97621071a03f3eb5d4cc202790bf067304e16e'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-35', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', 'cc46c2c107241bfc942a52c5769852443582607f2344d97044e087a8192875b9'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-36', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', '1f7107cd02c9605497e063424b77b87694c698caa107cc51e4d269c0361cceb0'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-37', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', 'b062e663886fd784658b6a1064d47d6a6a8b549dca33e7b01af8b471d5e38e80'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-38', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', '9b18f5929a33f5aa1dfee9e669833255f97b3e501c8566cb01e0372bbbc3eb9d'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-39', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', '77efa1386f5f270b68b2d48b31d965333e3b473ac6f71bae7ceaa7772d7e5318'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-40', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', '734ae5ffe4be4be5a4e6525a3d25397218f8bbef91bb3a6a7de7d95f0c06d959'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-41', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', '0d43857e1935f0f275bb7ea451e448e908baee7d897b9c958b44faa57be10347'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-42', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', 'eabc933a5e2fd1d8e1a50f08c921e8a1b2b8777ad9a0d62bf0f72a43fd9bf232'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-43', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', 'b31fb5e7de700865164282df1fb1c867ee208dd7c759fe17de3db45177b2deb4'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-44', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', '815530b5790aa0036c2cfd0ecb651e51ee58e8e9eb80b7ff92f2e3e6a95b1ff5'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-45', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', '44f4cc1441d83eca063ffa6ad8cf142bd64fe3ea0591900e69d96a12da0b2605'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-46', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', 'ce1d66f5a464444e90fde8741a35bdc78f7729679c3634cc0ae4a05443b1eff1'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-47', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', '411e5bf1d70d6d96c1b4e01e9ee5213af54ca5a72412c8b0592e494af076f77a'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-48', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', '562f59593b9b2e583596685cbea196ee76cbb6230df6852b214610d7a7b66ad7'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-49', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', '257a9cd1b4f61f081a6705b48e2ad5149558508e9b53b1ee286c2882ab7a0ed6'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-50', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', '0367b0e1f73b35fba503369c0f611ae35ab3762bae78bf5870979ca158545ae7'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-51', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', '259397d7f996149befaacc7b429fbcb5f737c5b9b05fdc65748fbf8b9b304a94'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-52', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', '65393044a4f453b7c6cc702ae0c512c958c91088e969525bf4d60502339015c5'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-53', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', '1b8ba23fa30a57985001e3b8ebcbf99853b668f28385c13012ab7087594d5d07'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-54', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', 'b1945a71c255ee2022285a9a2c989cbce98cf3591623db3f3b91ae22037359a5'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-55', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', '548fdeecbbbc8a6c374347a9ca53f28cc396bceac0c4491e0498b02ebde8fa81'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-56', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', '1d2094050a78cbec7fc31731eafbd0d244a6c6bea4a7c8bd3e9725e6456b7f09'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-57', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', '04fafb061da354a072c580fbfe91b4fb335327c75770c27154f93e0f924a61bf'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-58', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', '00edf7d5be54e86f836a678eab751c8cfa4aceba6b142b32684f4ef6469f612e'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-59', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', '35375bf3ba762ccffbdc6c5699f3bca155aed6f1577e9dcbd2ef1f8210ce2ae9'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-60', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', 'fe097d5d7809d7931f001d96978a17237a5f2faaacc02efad90af736975d681a'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-61', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', '7e79e971dcfbd3959398171fd47e8e945984900a0e02f4fa1cbb8575327c7cba'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-62', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', '649e4db4e87f34b3ae1a6fc9b27d874ebccd4dbd1ffa70e618dc594339f02f37'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-63', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', 'c7259d6e103f22f54b9e859015ace5cb179d5a17ffc70cb03593990d659ddff9'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-64', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', '9dc68891a727dcb17c132bf72dc815a866d55348af53d50c4399d50d8d4d7d79'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-65', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', '42519d4143b8cb81c63fd0a7f70bb432f2167df7ce27ab29d22311e0eebede91'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-66', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', '07009c784ba046eb7df3d9ff58906f4dbd7d03680b2bed50c0345d313a44b849'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-67', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', '063fac507fb0e2657548ad8a4f154f46900c461ec58da633a663e17d1eb68816'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-68', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', '063aad1ee73e16b3ee35c9cc5e28a2b844f7e5df0881685cd5eec3ea9d1cd090'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-69', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', '918ad339f4dd28b43403e47e763365703972307254f949e374913368be215053'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-70', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', '1c04d72e9626e861f03c228efd40560554e5741ed31cf2ed58b27ebc93eaab27'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-71', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', '3d99a542f01c5242c898c2aa1f58feddbd88de1a3c12d950ec9dfe5fe9742a4d'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-72', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', 'fe0d0eee2df6bd4b2e183e5f598c3b19f03a81cabe14025a42d175dbd8b4754a'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-73', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', '2d064e22a15387261b0e6361d3656d5290735087536fb1baf93c705a97fc21c4'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-74', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', '2a2d1fa6da10137c249f31153d3af3aaf53c9e366f8fcfb8ffefee18e55b18a1'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-75', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', '9229a83157f0f8b3b486415a76d95e2e2564d3a1350f7ee1f1668d8f4ece9764'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-76', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', 'dec09f830a7a2d2ea74b767c723451512e335c9d3fa107d4641f8b66d0b3bc57'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-77', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', '336ecf4f0598d32b9c68fc41caa1011b0fcfe6355a91d64642e71679b002a3b4'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-78', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', '73a44f909d02fdba3dc945aa1223d7f4416e9305e4a6fc69af43bdd62deb2bf1'),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-79', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', '14f56ff153b17e341e549404dfec6c20ecd9eeee0e5b0896ffeb8292a1c4b764'),
    ('nfa-test_display_deleted_view_preserves_bel_termination_and_nonsecret_parity-0', 'tests.unit.core.test_primitives.test_display_deleted_view_preserves_bel_termination_and_nonsecret_parity', '4c7a91461df07289d722cdead72d0e82ef8a5714df18cb6e7164d25fb37b3b77'),
    ('nfa-test_display_deleted_view_preserves_bel_termination_and_nonsecret_parity-1', 'tests.unit.core.test_primitives.test_display_deleted_view_preserves_bel_termination_and_nonsecret_parity', '6ed2c6422b7be55c0dacd463e8b75206d586038ec392d2c1721e049c52c4e198'),
    ('nfa-test_display_does_not_orphan_value_after_guarding_secret_key_context-0', 'tests.unit.core.test_primitives.test_display_does_not_orphan_value_after_guarding_secret_key_context', '2ff5ac077c26be74c0dcf01ce66cb8134d4300d055390986ccb7da388733bc57'),
    ('nfa-test_display_does_not_orphan_value_after_guarding_secret_key_context-1', 'tests.unit.core.test_primitives.test_display_does_not_orphan_value_after_guarding_secret_key_context', 'f2b21dcbcac2a5b21ba08bbafdf6ec0e364745d4785f3f6504d30a7dc768c170'),
    ('nfa-test_display_does_not_orphan_value_after_guarding_secret_key_context-2', 'tests.unit.core.test_primitives.test_display_does_not_orphan_value_after_guarding_secret_key_context', 'dd53b0dbd430817b1b05332ac9ae8b6012ada9120c441ddfbddc2694c4ab38d2'),
    ('nfa-test_display_does_not_orphan_value_after_guarding_secret_key_context-3', 'tests.unit.core.test_primitives.test_display_does_not_orphan_value_after_guarding_secret_key_context', '4033eb75823da5798536f8a38c6a8cd22ab836cb8d2d4c2e82984990ddc1f3b1'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-0', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', '5baee58613b0def6fcf0eeea188ef778993bdabce74ec14a53084385c210acfe'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-1', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', 'c05e71394255f73f553ad432500c0bfed6c816550bea372ac1ce52d3437fba13'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-2', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', '631be0cc1f960283ed404c51d288c1b9f8162475660963b6e4e1824e013d9655'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-3', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', 'ec6f8796831484c84266c7df989884f9ee76a3fda86a1c90dafa751b86219cac'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-4', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', '87f6e602aeecda9a3ed2c54789c899fc185ce5b42f747f75ca2a45b9d4b001fb'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-5', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', 'ba2d2f2905d731bd4a3f805f23fcbdd329a3215cf1b90e9691e9390c451bd3ec'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-6', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', 'c9eba438362a439bcfc5683a81a3f3663f200806805b37b60a26be6e00137710'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-7', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', 'c3965de24853391ee21ddc707a32e036cf0a2fbc1e24742d6d7b084cdd713a10'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-8', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', '2a70c354b9e1d3e502a737f132215d5687aba3494de1b9b77c44c6cf4d1440d7'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-9', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', '0e057a382e5906e06c7911d626ac22d6d422e6de554f0232b8e0ed5c543df881'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-10', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', '0a6dff7dea340ea15845b0dad2ea2c75fde088c0da4f356ea9595a0ea3d81365'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-11', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', '7e9da5eff455136e76545f1dfedc635e362c3b87342331e97a8ddd4379be10d9'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-12', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', '9e0f2cf4f1ee3716a855046b413891a35be3a0b88a93bb17b13b7182a08495fb'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-13', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', '4cce647ff0b3f513f983801dfcad61aef9224fd32e5e887b60cbb2c4f4ced9f8'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-14', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', 'a770f16b6c0cbfd4c3076ecbdde28759ead4623e929ea6bbcfe62aa54afff060'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-15', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', 'fdfa1b157e68ae38ed26ef106b1f07483209c7ac5e012dc72f0523da96b0b470'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-16', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', '007314b84f4d9d42beba94405b3a29996f45283a90e4312f0ab81b43b63e248a'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-17', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', 'c08f1e10fe4557cda6e1fbc04ec3a28070faf53829950e4be9e3d1c0145c4d5a'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-18', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', 'c01410129542a52a30f36ddaa95b13e66cb65fd2180f8cd28501fda078f73e85'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-19', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', 'f33e8a50d25c376df73a309d2b5db6874fe8f75e053ed098176b965870065e07'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-20', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', '0e3e23d20b52a922a16605665393068336a77e279e8c5ed4408cf26467de5a77'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-21', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', 'ee4e79b4ec7295362502e28e95e45c7fab1edded9f6e5db359f3a908bd6d0678'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-22', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', '10e8a8052e238159cff1ac3a1479e90d5109443f808613a7f69740d577eda7d2'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-23', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', '7ee37a0246f61e6918846c0ce494919855f85367c292895312c96de3497539ac'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-24', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', '522c5b364578062f8ff0f51bd2a87923f1d7e2d358a5ed0109f6f1dc6228d065'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-25', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', 'e39248017d19e91a31298ef2450f4a450d0b73aaf3dbb585fd919a765ef34b0f'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-26', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', '213b99723f8b261caf32d8d6b65d6ca074d3a1f81dc036ab3f9cd07fc673d42a'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-27', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', '941e84867f3610750dce30727b72cff4e175964573a6fbecbaed7a195a19a59a'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-28', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', '29807f4449ab6f5e7d686017fb0269e0fc4411ad64d12c2207f9db9d700d4590'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-29', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', 'a8c6cbb05018c178c821dcbf0bd11718505f07cb0c3c730de89738779ed34fcb'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-30', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', '2752d528277a57dec88a9d30fa72831560e526e793733d65f7e869bbcef021f7'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-31', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', '346a71a4640c0636db1017cd2149512df75fbc37a1f9777a75429a1d9c0009e5'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-32', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', 'c0cb5c93b1a4089a21d772bed043a5d3e17ff49f267c5edc22003bd4e549c1ec'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-33', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', 'a4d5d61c2ca5855915a05e94695328c07091b7a42fc59a15a5e421c02c75ce81'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-34', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', 'c0f4d9423ed19612f3f1cdd9c2ff770420f59ca9ebed04782da35c4830643a4d'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-35', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', 'daec38bf488d2074b50fc351ced18e414b6d9e4cf3a91e44b568a4913c5379bb'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-36', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', '73b3a2f8e3a051f4ff3867dca064035dd3bcfd4e540f92857336541e0a5fc059'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-37', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', '880e31297c818c4e69c2106078d0e66805b24a47e534f43bbc7fb64646222731'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-38', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', '58d1d9093f7e758a16e6026be327b384fb7076b3e8632281c502a1f80d13638e'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-39', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', 'e740f1881365d40bd89a2caad3406a0202a233d9b36617b236419a30cdfb7756'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-40', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', 'b7555082e5c4a488b52a2ad142be9846ca4cb16b562ce4b0d3975eb984969824'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-41', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', 'c5b36412150faf661035667cc1b1d43a6b933f6bb0ac8039d3c2196752923543'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-42', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', '40bd5e0563051452a4125bb76073ab9eac1f1fcb81ceeeed631d04a3cb015b47'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-43', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', '0a89b0fe560d6649721822d23848328fca9e06052a7f5b0271e07154a3cc8c0e'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-44', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', 'd02b03d25a61e24bab7eff30eb72a500f9549faacb77785956c8282861141b26'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-45', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', '55a75013c6dd9d52a6467b7f15955c7e4e7efdcd8e188dba3a9fc0112a3dab75'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-46', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', 'c683225b6ecf09e849fd02982c10d2230be4d6da2c3cf8eb60263320cc04b5ce'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-47', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', 'd900994ba303e6c0584909462b089108bfbbdfb746a0f0530b2183ce975d6d1b'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-48', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', 'b39a699d6159ce7537f647490be02944e0bc6faec0ab72636ec519f48faa9935'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-49', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', '378dab98c99ee345ba114bed6729e7d3f9f2d4d879cf69c6d0ea307cee3f6d97'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-50', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', '3a664ae7a89a3c7927114d0c2af40a211f46d9b91bc1c9b5c062539401f6f380'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-51', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', '5c7cf0921e012e705cbea60372bd216fd7c7085841cb3c9f201a965f4030f8fc'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-52', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', '41ea2dff6316aef976f328f851e408e331145d4548a2bddfab1e6329ab9f5667'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-53', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', 'f2bdd307ee7769a676678bc04c748b9d0a044e935ed96af433103cc1dbd01750'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-54', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', 'ee0363c89dcabe322ca350189859de1798749aaa4f343919f3656eac1687a730'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-55', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', '351d87a3e091e83a25bd592511cba34c9efcd9ffe3f886967d1fe8371aabca96'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-56', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', '9e3c4159127b09b58aad11eae9248f6293c34afbfbe51c1b798eb208418f0efd'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-57', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', '4a8cd53461706a5d839bf1f63c963a17f684387601e4a8ea49c469325a656f7f'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-58', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', '6f66d1f7f19958a10daf1ff87f524093db06495f3f78398647e6581cd593061b'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-59', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', 'fecd8038cfd171d3e5ba181a40787156c7e571af662415f947e8e449c42fd5ab'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-60', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', 'cb85a0663badca8b2d12ba1635142353bdf6609e55fbd3adbdb5b8255f91c7f6'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-61', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', '878fbb56a98baadf0cacc7954c07a71540f6eea0eb348a53b1f8e7acc77de2e0'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-62', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', '8dd8145cdb2baba1b3f2a956eec8f1129d68d94e1d79d7e8c220b462b1795f5b'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-63', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', 'ec7bafdfcbee295860b57a4e6b7bd32871e040082d1f3973f8ddf10db581dc2b'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-64', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', '7bd8b9cd60ff19385d1a26f59bb9766cdd30ef35187cb67b05d762e99e149b22'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-65', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', '7d02de52bedc8d9bc15a0a63f9c66df1eb7c33f225aa64894fd3efa2eea2f21e'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-66', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', 'c853462ff14a49d4eff3988a2c87fec827d911cde03cd3e7dfadbeaa22dc5add'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-67', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', '0403333595e135c33b2f2a080598316a15dda8f28f086c5c9bc9d100ac37ebef'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-68', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', '91f28c8922c10b9bef7fc77c0275aae6b084fbc40514b53a1ed077f27d5132e6'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-69', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', 'f799fed29306d9a8754e698b9a38d9c0370aba91174c8919aab1f19f38bf3e10'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-70', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', '688d272832321786d939a0d54e89aefcab1241fffe974719bbd8b84f9cbc8980'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-71', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', '322b1ac394582514c8b387d776492ba85310659446466cf912291f1b30159aa3'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-72', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', '91332c891d7350929580d082dfc4c1c4010d5d0b5af57b8a756f4446c5e2baf4'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-73', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', 'b48b14862a7b35a59bccfcafd2cf938058a6d7b2dce6bd316f976533d4f869fb'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-74', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', '6a048e9bde3e3ac1fd4e9bbaf470f01ae70dea01081af328b9ad7689c47861fc'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-75', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', 'de17c6210e0e4525b77f75b34a17087bccf065fc39168aceafa63c9a310462eb'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-76', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', '06ef719d837a612f4500d9b7bffe00835a63dd68c0716c84c290a84e40e416b2'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-77', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', '2dab922b8cc673d069c1ca64c55f1482c4a439479f99006bfad5f4f3d084026a'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-78', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', '1f96256271984f4f03e85e347a084f74405c134a74ac182cef006c8d70a37763'),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-79', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', '4426a5cae97259ef002bcb55513e4018df2e0f0c580f6be6ff20245c8dc98cb4'),
    ('nfa-test_display_pem_extents_cover_differently_labelled_nested_body-0', 'tests.unit.core.test_primitives.test_display_pem_extents_cover_differently_labelled_nested_body', 'ce59f2a380d0973b471cda1a2dd7f10c4a51abf8217ea7ab2c358e0e6c8581b1'),
    ('nfa-test_display_pem_extents_cover_differently_labelled_nested_body-1', 'tests.unit.core.test_primitives.test_display_pem_extents_cover_differently_labelled_nested_body', '9dfc64873f0e5b0f822fb5927196c7992cf0c53f3b5baf543b3b147a986040ec'),
    ('nfa-test_display_pem_extents_cover_differently_labelled_nested_body-2', 'tests.unit.core.test_primitives.test_display_pem_extents_cover_differently_labelled_nested_body', 'd4c5d4f1769a6f7e60c2f7f8613c1ca9ee665aa49bc747f2125905b5cdc912b3'),
    ('nfa-test_display_pem_extents_cover_differently_labelled_nested_body-3', 'tests.unit.core.test_primitives.test_display_pem_extents_cover_differently_labelled_nested_body', 'f8badd1a6ba194903b3bb346d0a9fbb21048662975847176b7ad770bf146c775'),
    ('nfa-test_display_pem_extents_cover_differently_labelled_nested_body-4', 'tests.unit.core.test_primitives.test_display_pem_extents_cover_differently_labelled_nested_body', '5a3baa9511bad67ddad86c683ba2aafe0bd534e0e084b57d53a0c2651f400584'),
    ('nfa-test_display_pem_extents_cover_differently_labelled_nested_body-5', 'tests.unit.core.test_primitives.test_display_pem_extents_cover_differently_labelled_nested_body', '08564afb03731197c2dffe70cf6bf816414164bbc12ff09428eb45c935938d36'),
    ('nfa-test_display_pem_extents_cover_differently_labelled_nested_body-6', 'tests.unit.core.test_primitives.test_display_pem_extents_cover_differently_labelled_nested_body', '798acc7b921bb915ef2d7add53874a43f6cd20ec30f6ba66d49c6fed67a50567'),
    ('nfa-test_display_pem_extents_cover_differently_labelled_nested_body-7', 'tests.unit.core.test_primitives.test_display_pem_extents_cover_differently_labelled_nested_body', 'df0017447b0b6aae4ef192ba1cb247a95c2de98c9690d0f12b8dddec4245ae68'),
    ('nfa-test_display_preserves_url_context_and_masks_overlapping_secret_rules-0', 'tests.unit.core.test_primitives.test_display_preserves_url_context_and_masks_overlapping_secret_rules', '44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-0', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '52ce8ff2f7b4846632657db58b77f7cc863b0c137d70326cc0ed52f7be6617c4'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-1', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '198b13e1e086841dab076d00f67435caed0b22c2b44e2b041819c1185464efc4'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-2', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '1c614e632dea88901e9c6f0f0538cfa46e504da1f98bca7265cd4b379b191f25'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-3', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '59da97704ad5a85958a5d4770e56a3528b7d13a9d17c4f084e11f5d8c4585b76'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-4', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '4096295349209cc926fca22e8dd2d52dd048679e43532d351f3092f04c990d70'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-5', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '87d697d7d8254f885471e9e609b13a3ff8898c8fae48b7564ec7abd337fbbc5a'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-6', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', 'b9e2fcad4309aaca956a14176705bda51d36807b65183f52f2f2d4a10f075cd7'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-7', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', 'd11762de019cfca6464b98c1590d3f02188401c5fd7d9349f5c6ef0c8a419e8e'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-8', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', 'b785239acc7d05508ddc1297a6d3a683c1ad41e91c474c4f6e12abdbab01ac4f'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-9', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', 'af27da34f462aa99153ee00c073d345cd2de42c9d116e6a0eeea8afb791643d6'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-10', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', 'e4ff079b1ab962fd2fc2f1fe5f271a2e5f37b8feb531e010cf59b35948f3861b'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-11', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '7a55df9f33ed1470bbd43c9d4163c99e27970585c2890454f4d68e5dcf07a0b8'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-12', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '19675ad1c271c2423cf5164856bba6094cbec6f8f40a4fdbc2f17b56c15625f4'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-13', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '26c8dc8c21a52076b91c576f97e186b228d2d98ec9f4e0b05e307f72721927f1'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-14', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', 'aaef1f2c0c124bcd328cdd4bafa7e03fe9823aed2e6ea156ec84cccde8deccd9'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-15', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', 'e17fe6d1a48a2558c5d9837728781783fe62f9bc7e2d7b4df7fd5cf010733dd0'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-16', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '44a7de3f491a34a39653decd50d91e5923f28a16082b6d559a34a37c41aab9eb'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-17', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '9ad3f800a4ed3087a0d4c7918f87ce36a54798374c429a0edc0e900904a38c36'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-18', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', 'd33b4611b2a5050e47bd6f94e621ce405917247af2fc8db09ec95feb7fe0700c'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-19', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '91084c28c79d4629c23b9713e8303ec7b4a904fef26f7809c28a1f4948150ece'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-20', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '9258c55d9fcff176da2835501b0f9dc653636048a4d3526717b0fe55a8b733d4'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-21', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '3a1e29704f7c757b045ae2cf50bbfa4dada7861bbe7b4a976f7d93542ad8ebd1'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-22', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', 'ec553215cdab185fa43fac4ac30eab72c5c90bdeb6cae56bc18643066e0b8847'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-23', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '9d3f775c5da3755ac44595667f97f077ecf45e76834a02b7436eb23a06d2e2d0'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-24', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', 'e82bb0ae7ecc730426284adeb5373658dd3e72a95626f9cf9ba1920dce68753b'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-25', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '09da122e4003a167aba99a83a031661d14042d24c438ce4bfcffdaa9d902a85f'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-26', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '7b6e6c62912a3eddb00a55f7cbafe1bb992e3cc6dd3754a5570c2c1bb21a6efc'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-27', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '4ded1dd57afa16a20322f6675c028e20f2562afcc8489a5f88c77c5e669ccb6c'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-28', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '8784e60d1f9208f94887c694d2f8155afa899815dc4906f6e4351182840b6103'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-29', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '32bafec0203544c82a01faf8bc579c4bcb2c046e92671e18d2ff5fdd511c1633'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-30', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '8cbf4b055efec0902e2f8b4d8670306c99ff1b4c5ec0b1272a853b294acaa284'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-31', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', 'be46252f2b575d994f3e7781298e04858d7d427e131a837ca5d90b19e072ad0e'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-32', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '2f24eedcdffe6102667712e2aa628ad3eafa6523055a962a69f5987dbc489156'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-33', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '6279931d386fc736d91354ada08307e904c4b4e064ffa4d72ad891f97a1a5109'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-34', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '4fda9376c498effb9a52b931eb0a84adbe59ed22d98594f9a161e013c413e9fd'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-35', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', 'd8d4360efaec2dddad111fc120675c9581fe74b54ae479eb5dd2141feb900542'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-36', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '9bc697d46385c132acdffc503e36d65e1f66df66b941bdc8daef4bdad112346f'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-37', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', 'a0a2f11eaa991b1f6b788697645be5e58954ccbc019bcb2dd788e768a2806ee1'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-38', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '1226437a37e94a678f71fc8db80885cae1d052dc2a534f3ff736cf8c4b6c7635'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-39', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', 'cfefe0f8a598b82b299fbd7f029785e57f0e6802e428cfb9a0ddc461a213c2d7'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-40', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', 'e65b9524c460a9dae3c8bd7ab92170e434c1695ab8a9c74644c42dd523715a41'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-41', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', 'fb7fc0ef8326b67e857380945e1359a22348594e5ba5cb5f59648b61cc87085f'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-42', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '56e681094b28c745065280f640b08e945b70379adf5d258f97ed86b69a22a6d7'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-43', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '9abdd3858992966c801aa76a02475d7f224c6f03d00996b89d7ebe24438f7d8e'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-44', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', 'cb9a4912ba4625cd9c78ddc2a11e8b88e7dd4c90356307c7410ed6ad616b070d'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-45', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '26c75529b92f3a7770210e77b32b153aae751b1a0b239fdab40ad014d554999a'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-46', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '804f89464d55e589b592c58acd2f91717bb0aca279bd4fc53c5803c254e28357'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-47', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '31e58ef738547434656ae0461a26067e157023b35ba09372bd3560514c57b6ce'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-48', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', 'b1a7fb533292797d0a6318307135568f70c069e28e8469734f87d2f51368d03d'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-49', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', 'ca097f427e018e4a0cf177328a113baf03bb8488c3ed197cf3466d4ddf43bc4d'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-50', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '2903ed2c0f9f316d10c8ac090e9822464ced9f6edb36238d820cbe9188a8c56c'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-51', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', 'f83907aaed5234fb074025fb8474b50421432a36aef4359cbb2bb86ecc275c5a'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-52', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', 'e15ec592c500bd98fd736885faf9bdf99a60e312c51b77325393b00391ad6c94'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-53', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', 'a3bfe092fdc1c73ef140424ea56f1ab928505d17c56654f19212be76adf89555'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-54', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', 'd741e08e9dcd9f571b4f7918eca80f19ec6c32c8afa77b11d0d321726ce95ac9'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-55', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', 'fc50283d8e734b5c033bedaffa99d9b3d5b8def3e47f35f86270c409936f771e'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-56', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '550b359d3eac6bd521c10713fbd7f7b89a1f463037a8e66b6750bb5f50282f2c'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-57', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '9599b05966761aa0ec0eca07fc4c946ba1c124c4078a2c533b1d4453b6564bfa'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-58', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', 'd5acd0dc4799803998313d0b8e295b9b8321eba68711a0ce66f001cf04ba74f0'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-59', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '7f1bcce858cb99cd9c627266f556b598bdb3e4cfb487ab4b4f4a5aa55037a57d'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-60', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '56d0902c2f80a339eb83965f29717079b03e3931ab5ddedda0a678dc8194522a'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-61', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '477051ab256c599dfbb1154e935adb74a904dc4983efd3cc37fec68a9028fe29'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-62', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '21efe36ed4472093b6ef0d0e594d88b519d7e6ed1ee3fd3c993d61178a6f104b'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-63', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', 'cc1467bb24a75c07f9d0ee54f537ca7a7467f63cd28c4faefc64af6245cc648f'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-64', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '944445e94888c14ece703ad93a6aa22989bf244855b12c229cf0b7408677565e'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-65', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', 'cef9d478125886549a0e4c96e131ab16132d94b55cf7075ec7ad968199361d6b'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-66', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '076d7d3794c0d063fddbe7fdcdac8b7608d242057ea0faacbbb94ca8bd4a4ad2'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-67', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '715618f4253afd87220520efdd605ea4a656b5bb981223b40e2ff3e4da523601'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-68', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', 'afa52de01d6471fd64c1008687e8f919b689bdeac364d5a6020d48616ea46a64'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-69', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '4d5e45b29e65a7c1332aa608b6a40f3a1b4c48913930c6586d50d61ae6b4442f'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-70', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '6a2cf15bab6dce99a8e29f53a378d6ad0c0f64183cc5668d6e63b7d84096eeab'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-71', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', 'c6f57be24f4a10196ea5beacc62d335f824564c85c9c86ab5c3cdd96f05b55e0'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-72', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', 'c18df51f857be0dff1ad91864d7c58e1421a0a47ea45a0faff918388b7ea3d21'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-73', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '3c211f73a0f2d0f28a24ab01ac15c57baad53ec1ef0fc7dc92059785fd03c5c7'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-74', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', 'df840099c3e7bbb07bbc2992734c3a59345265ece103527f71659fae51adb7ef'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-75', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '2013f7000f3faa1dc7049be1892e90d0f10c87c08918eac02ea9114530ff38ea'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-76', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', 'dae1666c455618a8f72b1ffbdfe88195d1e098283965a92a916a0950d1a0680c'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-77', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '5f243d7b513cf7dd8c2205f556883cda8529cb7c6b2eb1d98563bb9565aa9e3e'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-78', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', 'ceb3e24c4447cf897db304c25ca118aac81ae9f16c84721b80b6616a76829098'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-79', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '573f0074124cd9844eb925a47d21764cc4c6e6a5f88da69d6d3282ab9ddc400f'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-80', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '11c384b28e9edb1081ade7746a6ee438730506fca62a4c3e23ca45000d9eb276'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-81', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', 'a304a68607283436a32765a0cac675953e89526aa11c4ffbdf7e756d07d17ab4'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-82', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', 'c9ee63e7e1269e49e22fb712ed81ead6d7d8329c39bcf83431f08052865c84d0'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-83', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '1516d9f20948882501184f4e46192540af449040bc1a87f5e51df8badae15410'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-84', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', 'ca71cb8630fdaa3908fc1d8e2523e470ca94e55438f77d0a6bfde508635359dc'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-85', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '33ae994ad5fb53063a4cb9cc27388f5fb7815f7bf0b7d0c709f3c375b48ad385'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-86', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '44f14f170a5f4c6d9d99f6f3ccc0eb7c3ac551fc9d7815090cd5c31ac3864c40'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-87', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '7a2bd6516750fcc3f56fa370bc7c2590e94f41e93fa81581b88cedc83323d5b0'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-88', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '76a994dc931d3816dfe42356d8c1756b8f8ce9da2ceeea7e2f9d05468a206746'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-89', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '8e39ac7c5ba7180dab361152f1f4e104048fc0885b20e9f9e5462c618ae948d0'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-90', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '1719b80a2e149a53af8bb397dbc94dec48e340965befd3facab912abd65d53d7'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-91', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '56cfaed398d1c50267b70a42ed2a7d4092f05b783699a94495b361cd6dba0e98'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-92', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', 'ff3036380ecb795aecba6eaf71c0b877bd24108fb4497d5c27d3a95efc2cfeef'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-93', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '74fb27b92a681877484e958fd28536d16dd1cbed15d889b71ac44516f13f7d39'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-94', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', 'b3ef3a90ed1009d0e5e18e494882161c3b5790fca3f0f0a758710b87a0528add'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-95', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '58854f98724c61051d9adc513085cb46787755efd50409a2084583932f3a26fb'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-96', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '3c88a05deae5cc889680e87625d7aa4114b748408543b34167dc300a7273f68a'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-97', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '94d055ed043cfbb65875ed1220ba286b4de00f84a8ff2ecc0f07ba0245a4f38d'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-98', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '89ad690fb65ce8d5b6244530c1ea46acf7ed3617a92cea8f1798c6729e4727c1'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-99', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', 'de9cdc9f4ae1d974b1f91763052978bf67b62dee93afdf5da8b9e54139478ff9'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-100', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', 'a85aaa8398e309c827d5f05686538ff71568259c8e951567bb958b6b6c4bdc52'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-101', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '8775defb87fb708ddae870bf2e0cec5d45e607d98bfafa1a1749599a91f07b8c'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-102', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', 'b49c1f70815efd55d936f3997a04a093f705dc2c4f0f3267808136b3855a9a7e'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-103', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '7b4e9132c2b7b424d4eddefa5645729ee0d8b146e1598ebc5642a0baa157bc78'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-104', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', 'cf6ed4d4c8386953026343cea0dee81dc1c276a00ea9fba2113dcb5c6046429d'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-105', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '2eed5465ed90268cbb2cd4b6776fb168278f3516c3c0cf840d72595c54dc5e1e'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-106', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '2dc19035c63a85155f59695b1f8343a2f7a551c7675a600156e825072ea395c5'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-107', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '495c398f65ba8f0fd938e299ede4920df5a564bfe5b67d6a0d0be0aa23d69bea'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-108', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', 'ccaf92670a41ccab3599ac47ec4910aae060692b93345f6f923535667a45e7c1'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-109', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '2e6c513898ee5d1b3c84b5919714f58386fd8dd864a765319089082f002e3046'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-110', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '443c18d8d797dc60b16af04901d54ca9a62684e003e9a4bd0968a5e56b2303f2'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-111', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '3d05bdc794f615dffbfa49fea3789ab7d6a9e5eb053c60e61ed6e0d4a0d198e4'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-112', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', 'ec257f8a337723d2be9c2400f9856050f970f65313a7e18715265eb8bc33da4a'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-113', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '75d8ac56a55f68b2bf4aeb5f59863f74be1b08a1c0d95f4aa5f4113fcd3b86c2'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-114', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', 'decaaac964b8969a1b61714b862d6e7d9f1ad3bd3479d2f883fd27caffec3eb9'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-115', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '7c21fb350f1811f0417f3a8ed0d1979840e58f5b786a1d5fdf1ffb784e808828'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-116', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', 'b9211934be73c549c880759f5a5d449d96a757288b60d239adc4f516ae56270d'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-117', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', 'f753f317c9edd969746f7d2887132f14fe33c224df2d5f1662820add74bc9414'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-118', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', '79b5c8d3b822d504bee5cb93dc6d67fc8cdc15cd7fc281fcb69390674978b770'),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-119', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', 'f47923eccd286c991d901d22c9054ea2652c285a017c00f72a406a710304af8c'),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-0', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', '06e50daa8ef10541aa9b5e35c18e3a50b3f946678a2c42a0cd918c7b7ef263f8'),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-1', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', '9a8165e082b1e0909671d7cac9d1f880baf63f4bfd868b2a7b9a084936798c62'),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-2', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', '4763a1d9735c247fbe4f8f51c9a506e276e6d1088e8278ecd02a555ed1c4f4b4'),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-3', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', '97e1b7935f737f09e90e6a661d9218f455e0e038d85cf5996d87bc4f8bef5738'),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-4', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', '80e6c4977635bd0fb9895bff10680e36b6e8503eee39fcf2b78e2d9bcbc20423'),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-5', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', '2563d8085703b120f74247faead8e244b760c89981822faa3b9d70faf2f1d4b0'),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-6', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', '4080d823d716cb84d0dd5ad57e52dace42754a1253eab102d2a07b1823465858'),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-7', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', '20416c4827c764f952e10695ddd8802533ea1c482786661cc69fa7230c6d6e8c'),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-8', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', '6da9b756d63c6b11788b3e4071876006e38612336eba55991e8382b0d51b654c'),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-9', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', '49679da960c996e2ea6d3daaa4d5edb4e11591605755c55858c8ba8460e5eb88'),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-10', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', '838975a1057b8733c513412dbcd03812fb76fa47d69191c73e5e0bfe06dc62d7'),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-11', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', '7c32aea69075486d834c32541b81145c294345c2e8945a2d62e9e4b7498c055c'),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-12', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', '602a3c76e42496419ff01fa165bc5d70842e5396da389b10012e6954d29deec4'),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-13', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', 'e777536fdb87ec3f1fabb9b23c2e88b4cec7f557ce619d87be664959d2827a54'),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-14', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', '62f304f465d1d3181ee2038503b526d147d3536136ef6e83068d3f51a3103e6a'),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-15', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', '2b46c9f60df1fd2c49b6563deb48ac8d54e51650f8b90172345fcdfc6b9af735'),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-16', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', '52f7a8e3e9930aec25036100a6eea6b4b950d8520b5c1c7551441b821557b6b2'),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-17', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', '6360a9b75ad92e419f2c23ac3cd170c004a602e6e4bf7feae5a8983f1152000e'),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-18', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', 'b32f8e55672f9acd85f62b83d1dde8cc973c6f95f0189cf0ed2345a106673928'),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-19', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', '86da0108a036da3d97adf32e5c19a34c9c0e3319b956c7de5da5d956c679d78e'),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-20', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', 'db98e66109368c764b98eee8319288e251dfab0ddf2077d316e4e88b896b9155'),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-21', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', '0e749127433fa8f0c476727e5371c9748e3c16d524ff300ece5c0cc044006e00'),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-22', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', '8db850ed4e94390ee4b9e97557da8765f496a5c5d85c8b6c27fe97cba9873e67'),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-23', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', 'c46813370a6be4a929b35728d8eb94d23d77e7276b1dd037b4c315dd4b98ada2'),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-24', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', 'bc0069ad34a87f5c614f2f87c3c3cd60286ee2d7d2339c5f62ff5134d023c41b'),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-25', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', '6323f3a3a69da119e5a9dd71c3638a87747f94b1185d9b26a6355fddabec028b'),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-26', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', 'b528fe0113dfc3f946841836e0c8dade6ddab51977c05a7ea078d30d83566bf9'),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-27', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', '77eab4480500608f4dc379736a9a4732f6c88040b2960301f4f56d760e9cb241'),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-28', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', '3b6af8e24e5c3aedeac2cb92707a6c845e97c9a67814b66768e548b392beaeb3'),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-29', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', '7d65d7cfb65d80e7ee3877b743c258bb6c2fcf3afe7a60147fc6b23c3a4b2e1f'),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-30', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', '68839e275ac404080209900c5f170c27892b3b8059a8b47690830869ca208fb9'),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-31', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', 'b8deeb4ed06ac12c9a6e4bd2351ce2eeae1d92adf358fc7247abf949375587dd'),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-32', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', '2498989e01a2a2ec4ae6de0ba26eea06b99c1dee1bdd4f9f01071809265a03a1'),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-33', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', 'c73f15a1d2330093764cb55e5f8647e28dcd66d138a09a7f546a2b113853e7bc'),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-34', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', '1ed5ea643498002a13a1dde94c977cf4174d6e72205e3027ad9aee80b9ae54ce'),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-35', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', 'cacb7baff22a1e9dbf838aa61052b3cb11ba4074d6a57e1827b9a3ab41441a98'),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-36', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', 'a2f7a6ce1e9acf9598e3d804f7f44074adbc5ce49b172c3fa6d8e9c223732926'),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-37', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', 'b7d3fcce3becc589ae6dbc786a4d8e8c86f5731c43487193cdcd5e9084bf9d83'),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-38', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', '582154a29f7c6d3a12594692789622794274963a025601c6bd4752589a2c0b2f'),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-39', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', '532079b147f1673139dcece49342b585f8c649aae90b083b4b7a298ab06efd9c'),
    ('nfa-test_display_provenance_masks_overlaps_inside_an_ordinary_match-0', 'tests.unit.core.test_primitives.test_display_provenance_masks_overlaps_inside_an_ordinary_match', '3f6a3a288169f08c9bb95db27b4ee9f6983c1c17f8f93694246da914063b49ea'),
    ('nfa-test_display_provenance_masks_overlaps_inside_an_ordinary_match-1', 'tests.unit.core.test_primitives.test_display_provenance_masks_overlaps_inside_an_ordinary_match', '652fc68500987bec46252670116ecd113fa55a2bd9d2732df108783e5918d7f2'),
    ('nfa-test_display_provenance_masks_overlaps_inside_an_ordinary_match-2', 'tests.unit.core.test_primitives.test_display_provenance_masks_overlaps_inside_an_ordinary_match', '5a942678b479118a432391f5439c93814b575b242a8b8f4b89248f5ef636714f'),
    ('nfa-test_display_provenance_masks_overlaps_inside_an_ordinary_match-3', 'tests.unit.core.test_primitives.test_display_provenance_masks_overlaps_inside_an_ordinary_match', 'adb745657429ef919430792541ece16e5366547f7140f3d1f4764b1f5ec13a87'),
    ('nfa-test_display_provenance_masks_overlaps_inside_an_ordinary_match-4', 'tests.unit.core.test_primitives.test_display_provenance_masks_overlaps_inside_an_ordinary_match', '1d123d66852811e68d58c4b6c612f46f064a82d95b8cf02fba8a25b9a1c22d14'),
    ('nfa-test_display_provenance_masks_overlaps_inside_an_ordinary_match-5', 'tests.unit.core.test_primitives.test_display_provenance_masks_overlaps_inside_an_ordinary_match', '11175bc42d5ca1933819fae2874431a9b89f284643123da3d910bba8f858f7e9'),
    ('nfa-test_display_provenance_masks_overlaps_inside_an_ordinary_match-6', 'tests.unit.core.test_primitives.test_display_provenance_masks_overlaps_inside_an_ordinary_match', '6c11268b66906b2226111c47562e9f4c30a799b9d9c11a07f76b2a31e76232c8'),
    ('nfa-test_display_provenance_masks_overlaps_inside_an_ordinary_match-7', 'tests.unit.core.test_primitives.test_display_provenance_masks_overlaps_inside_an_ordinary_match', '5e01691e55e89e47184cf75b58fb3928b42d2bff9f4e3da5315223fb2f74071b'),
    ('nfa-test_display_provenance_overlaps_and_headers_are_independent_in_threads-0', 'tests.unit.core.test_primitives.test_display_provenance_overlaps_and_headers_are_independent_in_threads', '2ff5ac077c26be74c0dcf01ce66cb8134d4300d055390986ccb7da388733bc57'),
    ('nfa-test_display_provenance_overlaps_and_headers_are_independent_in_threads-1', 'tests.unit.core.test_primitives.test_display_provenance_overlaps_and_headers_are_independent_in_threads', 'f2b21dcbcac2a5b21ba08bbafdf6ec0e364745d4785f3f6504d30a7dc768c170'),
    ('nfa-test_display_provenance_overlaps_and_headers_are_independent_in_threads-2', 'tests.unit.core.test_primitives.test_display_provenance_overlaps_and_headers_are_independent_in_threads', 'dd53b0dbd430817b1b05332ac9ae8b6012ada9120c441ddfbddc2694c4ab38d2'),
    ('nfa-test_display_provenance_overlaps_and_headers_are_independent_in_threads-3', 'tests.unit.core.test_primitives.test_display_provenance_overlaps_and_headers_are_independent_in_threads', '4033eb75823da5798536f8a38c6a8cd22ab836cb8d2d4c2e82984990ddc1f3b1'),
    ('nfa-test_display_reassembled_tokens_use_markers_before_caller_redaction-0', 'tests.unit.core.test_primitives.test_display_reassembled_tokens_use_markers_before_caller_redaction', 'fa7cab75c21b0198e8e724403a446d351694e195b1e00bb0dd72667235c6375b'),
    ('nfa-test_display_reassembled_tokens_use_markers_before_caller_redaction-1', 'tests.unit.core.test_primitives.test_display_reassembled_tokens_use_markers_before_caller_redaction', '7866c67d4eab7d1b31a64fa61899b117237dd1406ab7e0846a742808e6d906a2'),
    ('nfa-test_display_reassembled_tokens_use_markers_before_caller_redaction-2', 'tests.unit.core.test_primitives.test_display_reassembled_tokens_use_markers_before_caller_redaction', '82eb96cecd10a25e0c983ae8a2372c8b4397db421386830adaa1b8901e4b1b2b'),
    ('nfa-test_display_reassembled_tokens_use_markers_before_caller_redaction-3', 'tests.unit.core.test_primitives.test_display_reassembled_tokens_use_markers_before_caller_redaction', 'b565482446cf33e9a7ef9c95905ab9974f2a1e59e05553db182470eb6ca80377'),
    ('nfa-test_display_reassembled_tokens_use_markers_before_caller_redaction-4', 'tests.unit.core.test_primitives.test_display_reassembled_tokens_use_markers_before_caller_redaction', '720e847cc69e0affa097b10ec6e9f9f69a863a7407accb384aa0344c017d903e'),
    ('nfa-test_display_reassembled_tokens_use_markers_before_caller_redaction-5', 'tests.unit.core.test_primitives.test_display_reassembled_tokens_use_markers_before_caller_redaction', '38cb6cebd577aeb2b4ca37f5b7d3e6b6e995d6c8febf90dff009baad0c0ec5be'),
    ('nfa-test_display_reassembled_tokens_use_markers_before_caller_redaction-6', 'tests.unit.core.test_primitives.test_display_reassembled_tokens_use_markers_before_caller_redaction', 'd57bdddb0ec1370699da62d2b641b6e478ee257f0b382f227cb202ee7a538140'),
    ('nfa-test_display_reassembled_tokens_use_markers_before_caller_redaction-7', 'tests.unit.core.test_primitives.test_display_reassembled_tokens_use_markers_before_caller_redaction', '1fcc7de0e8b1a1fcc804ad613f880543c27861e4095469a654099f5ca52f6180'),
    ('nfa-test_display_reassembled_tokens_use_markers_before_caller_redaction-8', 'tests.unit.core.test_primitives.test_display_reassembled_tokens_use_markers_before_caller_redaction', '84d1ad8b84a58d2bf7533211db9a4908a45ec14083131968e612ad375ba5abfb'),
    ('nfa-test_display_reassembled_tokens_use_markers_before_caller_redaction-9', 'tests.unit.core.test_primitives.test_display_reassembled_tokens_use_markers_before_caller_redaction', '1850d4b05534d9be875966e23a8665bcc547428fa4071e5105818e4d16494747'),
    ('nfa-test_display_reassembled_tokens_use_markers_before_caller_redaction-10', 'tests.unit.core.test_primitives.test_display_reassembled_tokens_use_markers_before_caller_redaction', 'edfc183bea0e2ebea2258bce562e4773579b9e15163594f4968d937b6874b727'),
    ('nfa-test_display_reassembled_tokens_use_markers_before_caller_redaction-11', 'tests.unit.core.test_primitives.test_display_reassembled_tokens_use_markers_before_caller_redaction', '39255428fe91a65efac0497739b4c76a04c8431b7f78f78772256562bc825ae5'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-0', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', '7a97b9b4d758a3929b8a2be53fbe189c9ba9378d6fbb8190d37f7cc14f5cf5d3'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-1', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', '33c1c92944a084e89ac8cbfe15da3c741575cbddd50a0301b946fb6da8441a93'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-2', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', '4e24ca06368d462fbef4a405db418a4c57b23f0b643b78d35370fb6bfd8f664c'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-3', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', '5cb191dc49f5600b79c8d2406515f75d5eb4a528633cf2802efd255bfe009668'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-4', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', 'b6fe401faeb9b7c14b3812067f017ce19e04122fd80d812fe1580e5583111fba'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-5', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', '3caeeafb6e3e6aeed25d2565652103d733d2b9d1412fd45264db6d50c16d8a2e'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-6', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', '192bfed6b575ea9bb135df86521c425714c023363df1671720b397c54c18019e'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-7', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', 'a4fd3aab352c00201055b619369c8d05727315a64c743850f11b583a7306b940'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-8', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', 'f1a6051e20cfb900e70c85aaf7bf7f008462d9b56f95f00f673b067ca0e0d0ae'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-9', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', '006bc09a1498874b1e271f6c8cf4cb88ceb7c2b5b6e42f684a3dd5157bb15c45'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-10', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', '8e9efb996c8d09bde527d441ea8a0704bd18c952d6d1fbd5d43bf6a3e753cdb6'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-11', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', 'b1fde1a1aed60383aa570e42117b740d14465026d4a0c2c84b6a4fcdebce6962'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-12', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', '0a0ca49956ec625178675dabbf59dc8ed0e009506cb93400dc000e63b48eb75b'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-13', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', '2484f64415a74a8ccbf155ee55b379f0a378683ab9a42189009cabb4b77b8d7b'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-14', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', 'd24453236d007b02015fe5d8f4439464b1399a801c8694691d04a4f6d59dbb1c'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-15', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', '1025fecf75b657ecf610a2386c1497aa715cd58a8442206fc42a92a681b02b57'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-16', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', '33affce6bc4856ace693dab78cf2c28e7ee48795d041fe0f7c4cff24528e881c'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-17', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', 'dbc7a93b0db6ada49563e962823feeb06d6ff37caee8f136db030921120934fe'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-18', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', '69efeb092ff8c67cf726bbfd6c5b39a1094192fcb4690bd7be7ad8ca216c1f15'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-19', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', '7292bd1451b5727f35c200803e21c77599678dd4dc1ade443cca326fad4c0cbe'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-20', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', '90dc47fb25e199ae366eba4735b0735202666adff2d11da1c90efc1797115241'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-21', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', 'd876aeeec362a464475e15d566e65c34ba8ca502143b824645a6f65eff97bb79'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-22', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', '38265f94aa7d7d8bee533847ffd284192309282a707a2f94256601a3f99b38a5'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-23', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', '6afcf28b5af038bab3b754231a723cff8be638de183335d2ce00fa00f9653587'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-24', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', '39eb4a2f617fbca85b833ae3938ef39ec09ce56d45e52832ae04313a629f8529'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-25', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', '9742e6453d458fbd4e93a59eec970e77863829fac54ce080e5378636d5acdb17'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-26', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', 'a5e85b573ae4cdec255e4e0abc8fa5b4a52349f37cedeacb6ec91f664d1711e2'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-27', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', '918c7a863cefea8a1a71120cdad952b6fe35601baee4fdd5bdfb4e58008936b9'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-28', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', '6f07b80ab44d7832499cee1f23d03445adab2187d484fec9d22172c7b3eeb74a'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-29', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', 'd4029fe5cd1feb401f7c3e0932ca7bfc1ba08504eb57d23885b0c05b3037b34a'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-30', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', 'aadde57f80523708724b29d42ef7a0958e69e94950d54e7178a05ebc87ca266f'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-31', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', '7ed6fb9ee44d3d26cd0bbcbb6c470b15ce0b17b9de09def4d53febfbc627c185'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-32', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', 'c5b082a7bcdface1883f9af5697b9bfcc0746fda62ce726e70d2abf427790828'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-33', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', 'a931339211edbbc27a9aa852da41f035bc321a9aa3e58fcfbd7e94b9b7ffff9e'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-34', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', '7502a96165df8e6ad34622ee9ea807151a5ebd456e1d08f07cffe9d66bced87b'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-35', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', 'aeb0469517967c2e16c8e0a26a0dd443c619fe11c711e7a7755f8460ac0d546c'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-36', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', '548e89ff3da179274ea4e640d6fd167123297ceed9043d60fbf552c5b41107d2'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-37', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', 'e11d31165ad7ab4ad866db3dc624f651851076e89801232bcbef18c16f1cbbee'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-38', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', '69d511387ad64535a7832b623652a2fb4e73e408b427ad1fe97deba896bee1d7'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-39', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', 'ddd013385625a40f1b1285e94805375ce34bd05d8ad064338f27ee16a36897a2'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-40', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', 'd153c16b1cf1dd72fc0473ea8a554536ad4f802a3dadf211fd4d860faf3f2744'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-41', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', 'cc832b071064ae570b93c15ee0868209df9f37e72f8fea4c6ee1a5b225a586dc'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-42', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', 'b635fc73951e2d61d1cdf32e396293db851ee8bbb122961d3228dbf9759dc49c'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-43', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', '9b03de4fa56674f09f3d153383faf3b51f56e51759cd80f8dbc4d8e156c0b8f6'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-44', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', '5b1e9c8e83d8b85563b7ffdcef9c2e582cf6947a0ceef0e5898d2b80c882f8c8'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-45', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', '4258666cf1a1c751482d3f96ba43d5a1f2471c29da22d9334dd011ee8f39112c'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-46', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', 'a70a96e5a7efbb9fa3e1e3bc5a94691403d42673567091bc55f14173558d2a34'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-47', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', '660b2cc6888044ebfeee9687481108b16c0f8745ba652397d4bc82d0a422aef5'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-48', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', '568f2f6ab31f07e1d36ce72e9d1dbb0a03e0e49e704afbeeec9bfc6a349d253f'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-49', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', 'f7bc4438b705f91f3593723008ac37504dfde6ffd5457c68cc1aac155211f942'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-50', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', '7a5a9ea534e5fd632972da20e2028290f8e73d187d83ad57b788941a3a7402c9'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-51', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', 'f634329c2d2b4379f096b2394be9c26cdf2f86022ff24b8736b59797cca04d33'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-52', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', '9885bae9d93ae0923d4c5371151d3794e835ce5684bbf6101f0b616e82838a37'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-53', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', 'a4adddbcef998d9b9301b31bd3053748aea6ec09d00ef87655c7ebcf7440218b'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-54', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', 'f30026fd8c69498cc5fbf2f7e73bc95410918186378ec472aa3078d81d0c3e9e'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-55', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', '774ac1458650f9e4859e215fb05f2ecc1822ddfa39639e62a2727e807820ee45'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-56', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', '576e318461e9f9ea9f46e9e276d7a30ae29d3ea54c36f2822f012e16544bfd31'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-57', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', 'c5ffdb69216e2f61131514b0274f467aad6d5c7186063198496deeb801c4ce70'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-58', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', 'dcd4bc0da687c0c2edcb9accbdadfe43b4bef7dc5d5616367ce7da2add97717e'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-59', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', 'c56bf46415a8b41f8af4f74103142bd07611317aa1dbb39f2598e239181d5b36'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-60', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', '34beda16337343b11c38216657aded86f64ddefa8bde190b5ac005a844cd1204'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-61', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', '1b1bada3de5d067eaa485686f0585ef53343a0ab04b21265e3e2e4521d7a01b5'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-62', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', 'fe4852b08c5ccce18efc73dadc4f39a31829ca878d98de20797d1b9145685ce7'),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-63', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', 'ae6bbdbc405e721b66be1255f9cb969015f52105875595edef0ec438b0420d50'),
    ('nfa-test_display_rendered_segments_keep_visible_credential_whitespace-0', 'tests.unit.core.test_primitives.test_display_rendered_segments_keep_visible_credential_whitespace', '31bf54a370b35cd851fa1d7f3282f8fd6cec9f2bcbae83c772d947ee3ab4eb72'),
    ('nfa-test_display_rendered_segments_keep_visible_credential_whitespace-1', 'tests.unit.core.test_primitives.test_display_rendered_segments_keep_visible_credential_whitespace', '91ab637866eea9d936398b23a669095eb10887cbf641a7a31accde4333bfe000'),
    ('nfa-test_display_rendered_segments_keep_visible_credential_whitespace-2', 'tests.unit.core.test_primitives.test_display_rendered_segments_keep_visible_credential_whitespace', '543db96c03c96195c90c51232c587b4d574dcb2df88170ce36c16d08d8c1c7ca'),
    ('nfa-test_display_rendered_segments_keep_visible_credential_whitespace-3', 'tests.unit.core.test_primitives.test_display_rendered_segments_keep_visible_credential_whitespace', '62107a68c25ea743db14c49d9b3de1ebeb72547b41b5bfd1430db2dab3a5b45d'),
    ('nfa-test_display_rendered_segments_keep_visible_credential_whitespace-4', 'tests.unit.core.test_primitives.test_display_rendered_segments_keep_visible_credential_whitespace', '6e0fb9ce50e2f038d0db3a18e994616b4ba578a7331394577a9a8dab4e44faf2'),
    ('nfa-test_display_rendered_segments_keep_visible_credential_whitespace-5', 'tests.unit.core.test_primitives.test_display_rendered_segments_keep_visible_credential_whitespace', '00d5804e779ae4941e10bc3283086f6f2b4e375f532930d8009e0b59f2f2c216'),
    ('nfa-test_display_rendered_segments_keep_visible_credential_whitespace-6', 'tests.unit.core.test_primitives.test_display_rendered_segments_keep_visible_credential_whitespace', '833ce6552e652f6e605fdb00b871173ee885bc6d6ac7788e8a3ec61b262e19df'),
    ('nfa-test_display_rendered_segments_keep_visible_credential_whitespace-7', 'tests.unit.core.test_primitives.test_display_rendered_segments_keep_visible_credential_whitespace', 'cec342f2b6e9db02c13916e08458362b18d3f9978b3697c57732abb5534b52d3'),
    ('nfa-test_display_rendered_segments_keep_visible_credential_whitespace-8', 'tests.unit.core.test_primitives.test_display_rendered_segments_keep_visible_credential_whitespace', 'd8399d44cc65b49ce0651b6ed21594ca3dc5275b99e3d21d7a2d44775bb5d8bb'),
    ('nfa-test_display_rendered_segments_keep_visible_credential_whitespace-9', 'tests.unit.core.test_primitives.test_display_rendered_segments_keep_visible_credential_whitespace', 'd1d9a797c3374e2beb0ccc58b100e3de4bebf144cb71dc8e9034be05218244a0'),
    ('nfa-test_display_rendered_segments_keep_visible_credential_whitespace-10', 'tests.unit.core.test_primitives.test_display_rendered_segments_keep_visible_credential_whitespace', 'a2d0f1b537752d7182ba4d56805dbe77c5ced2fa8dda4a752a0904f74120c30c'),
    ('nfa-test_display_rendered_segments_keep_visible_credential_whitespace-11', 'tests.unit.core.test_primitives.test_display_rendered_segments_keep_visible_credential_whitespace', '1b4cf35e7ca94a6d523f2fd5e849f989ec87ca24dc78d97ae3c44d24f9e55dfd'),
    ('nfa-test_display_rendered_segments_keep_visible_credential_whitespace-12', 'tests.unit.core.test_primitives.test_display_rendered_segments_keep_visible_credential_whitespace', '99d3603f8c8c66ff37094ca002e771e60e625468fa11f24d6b6ac4270fa5ff51'),
    ('nfa-test_display_rendered_segments_keep_visible_credential_whitespace-13', 'tests.unit.core.test_primitives.test_display_rendered_segments_keep_visible_credential_whitespace', '25af2a785c9aec13de5164458e875e3446a0d8544d0ab70b02119b135495a5d2'),
    ('nfa-test_display_rendered_segments_keep_visible_credential_whitespace-14', 'tests.unit.core.test_primitives.test_display_rendered_segments_keep_visible_credential_whitespace', 'd4270d9c1975e05ae0bf2bf3cc48eb2d21293278929e01ff3acd815e0e69453a'),
    ('nfa-test_display_rendered_segments_keep_visible_credential_whitespace-15', 'tests.unit.core.test_primitives.test_display_rendered_segments_keep_visible_credential_whitespace', '07f0107d50e3428c67b0d0161a7c53f4c7a28e29fe77ef17a9ab25993e371f21'),
    ('nfa-test_display_rendered_segments_preserve_visible_space_inside_nonsecret-0', 'tests.unit.core.test_primitives.test_display_rendered_segments_preserve_visible_space_inside_nonsecret', '3684a6a82d95c8450953854cb86ff92a0da1032d4355f6e7d712fbc632b71e45'),
    ('nfa-test_display_rendered_segments_preserve_visible_space_inside_nonsecret-1', 'tests.unit.core.test_primitives.test_display_rendered_segments_preserve_visible_space_inside_nonsecret', 'f50a806d0474eae9cb865889c5d637dbb3aaef6bf6ea78d80fef85a43ce554d1'),
    ('nfa-test_display_rendered_segments_preserve_visible_space_inside_nonsecret-2', 'tests.unit.core.test_primitives.test_display_rendered_segments_preserve_visible_space_inside_nonsecret', 'e169c4df0b8f71910a24f66ac6d2d76ace99c83e801d26124432b46e565595dd'),
    ('nfa-test_display_rendered_segments_preserve_visible_space_inside_nonsecret-3', 'tests.unit.core.test_primitives.test_display_rendered_segments_preserve_visible_space_inside_nonsecret', 'bc1098ed669237d9ec662bbe9cbcad6aa964450bc50bc2af9d2b565c7b7290f1'),
    ('nfa-test_display_rendered_segments_preserve_visible_space_inside_nonsecret-4', 'tests.unit.core.test_primitives.test_display_rendered_segments_preserve_visible_space_inside_nonsecret', 'ce93a2e8e34b27f1fd090e0d4f65bc5b30d0a02c5519d8e8b1bf1644ab0a64d9'),
    ('nfa-test_display_rendered_segments_preserve_visible_space_inside_nonsecret-5', 'tests.unit.core.test_primitives.test_display_rendered_segments_preserve_visible_space_inside_nonsecret', 'c72dbab2c15dab7bbc6fca73723c4f0e724f66c76d1d9170cf47d3c2ffcc73c2'),
    ('nfa-test_display_rendered_segments_preserve_visible_space_inside_nonsecret-6', 'tests.unit.core.test_primitives.test_display_rendered_segments_preserve_visible_space_inside_nonsecret', '773531dbbe31e3d6f9eb7ec3cf2f4ea6928f984083b4e73b0c78fce728c453d7'),
    ('nfa-test_display_rendered_segments_preserve_visible_space_inside_nonsecret-7', 'tests.unit.core.test_primitives.test_display_rendered_segments_preserve_visible_space_inside_nonsecret', '33a7fce7aa25ae8db1d4d98fdebb18c18549898562004d23a59df62358b9ef4a'),
    ('nfa-test_display_rendered_segments_seal_hidden_token_prefix-0', 'tests.unit.core.test_primitives.test_display_rendered_segments_seal_hidden_token_prefix', '4251e6d450880a59b7a5ba3ea9c5a10827ec70ebf3d6b2e512feddc2b6da4e08'),
    ('nfa-test_display_rendered_segments_seal_hidden_token_prefix-1', 'tests.unit.core.test_primitives.test_display_rendered_segments_seal_hidden_token_prefix', 'e10efb592c9c193c7fe70f0f0db9e62a5a73b0dfc1c6e5819da42133ab53fc5b'),
    ('nfa-test_display_rendered_segments_seal_hidden_token_prefix-2', 'tests.unit.core.test_primitives.test_display_rendered_segments_seal_hidden_token_prefix', 'a40faa7b2013d8e73db6f2dc1b400cf770559c75e0fdd8534df3fa70250a368d'),
    ('nfa-test_display_rendered_segments_seal_hidden_token_prefix-3', 'tests.unit.core.test_primitives.test_display_rendered_segments_seal_hidden_token_prefix', '6231717d040e947bb9133c9244c70394401ce7f22b4b9265c0353b237e746f54'),
    ('nfa-test_display_rendered_segments_seal_hidden_token_prefix-4', 'tests.unit.core.test_primitives.test_display_rendered_segments_seal_hidden_token_prefix', '5ebde6290d5dd265b451f370d7a4b0431e9e8c52190445d8da1a1893391221c9'),
    ('nfa-test_display_rendered_segments_seal_hidden_token_prefix-5', 'tests.unit.core.test_primitives.test_display_rendered_segments_seal_hidden_token_prefix', '44b7dbb0c8a0463f317397e9324a9467e282523d77a77d05e30cc880f538da82'),
    ('nfa-test_display_rendered_segments_seal_hidden_token_prefix-6', 'tests.unit.core.test_primitives.test_display_rendered_segments_seal_hidden_token_prefix', '7eaefe572dffb8c48f3d100c0c852e74cc607b07e9cfbbecba21c28432015a98'),
    ('nfa-test_display_rendered_segments_seal_hidden_token_prefix-7', 'tests.unit.core.test_primitives.test_display_rendered_segments_seal_hidden_token_prefix', '96db07d3bb9e8de0b214bce5548a34a80de98d1b18ed047e15fea95f02a029de'),
    ('nfa-test_display_rendered_segments_seal_hidden_token_prefix-8', 'tests.unit.core.test_primitives.test_display_rendered_segments_seal_hidden_token_prefix', 'e24d2003fedfcd29d08814ddf7802ec8b6ed1e3cd681fb0fea1d0678ade010a9'),
    ('nfa-test_display_rendered_segments_seal_hidden_token_prefix-9', 'tests.unit.core.test_primitives.test_display_rendered_segments_seal_hidden_token_prefix', 'ae969bedfbebdab096186dae537a4598e2ac5fb99e117deaa2e53dd54fec7476'),
    ('nfa-test_display_rendered_segments_seal_hidden_token_prefix-10', 'tests.unit.core.test_primitives.test_display_rendered_segments_seal_hidden_token_prefix', '187647fa3df9c00feb7346d671098745b9c960410fbc523b3943090189e9dacf'),
    ('nfa-test_display_rendered_segments_seal_hidden_token_prefix-11', 'tests.unit.core.test_primitives.test_display_rendered_segments_seal_hidden_token_prefix', '2109e21f5575bbdcc8b36a81bdba3656e81f4363131cea862961ba8808fea814'),
    ('nfa-test_display_rendered_segments_seal_hidden_token_prefix-12', 'tests.unit.core.test_primitives.test_display_rendered_segments_seal_hidden_token_prefix', 'cca8e1f6015845d8f59234113dd72f7620a807188f387228eb8b1b7dd0ccfef3'),
    ('nfa-test_display_rendered_segments_seal_hidden_token_prefix-13', 'tests.unit.core.test_primitives.test_display_rendered_segments_seal_hidden_token_prefix', '012b7f351afda8504767ab592c32604840be6fc5c2d4933fc0c02cb7aff278e9'),
    ('nfa-test_display_rendered_segments_seal_hidden_token_prefix-14', 'tests.unit.core.test_primitives.test_display_rendered_segments_seal_hidden_token_prefix', '2f32845c9e31f3519994536cb12440f1ef754ad42c9cbb0038bbbd6989da11a2'),
    ('nfa-test_display_rendered_segments_seal_hidden_token_prefix-15', 'tests.unit.core.test_primitives.test_display_rendered_segments_seal_hidden_token_prefix', 'fe7ab13d202a3323e6a1f035b9a17b429f8e05fd1414b4625374f5093ee5323f'),
    ('nfa-test_display_rendered_segments_still_join_fully_removed_controls-0', 'tests.unit.core.test_primitives.test_display_rendered_segments_still_join_fully_removed_controls', 'f577a4cf1461026cdad8ba7e9e7fa521e05c7d4b769f989d642c5de661b1b2ee'),
    ('nfa-test_display_rendered_segments_still_join_fully_removed_controls-1', 'tests.unit.core.test_primitives.test_display_rendered_segments_still_join_fully_removed_controls', '6c645e1f61a0bd8be1c8fafb75034df941fdd88257a014a863d0fd242444c947'),
    ('nfa-test_display_rendered_segments_still_join_fully_removed_controls-2', 'tests.unit.core.test_primitives.test_display_rendered_segments_still_join_fully_removed_controls', 'c60c43632e81e3aa27b7f3ff52e57e14c8e18b4e257479646503b61177f9dfec'),
    ('nfa-test_display_rendered_segments_still_join_fully_removed_controls-3', 'tests.unit.core.test_primitives.test_display_rendered_segments_still_join_fully_removed_controls', 'efcf3b75ebe1238ec546288b7a83df6021be181c907ead5f0cf4156b5474b2c7'),
    ('nfa-test_display_rendered_segments_still_join_fully_removed_controls-4', 'tests.unit.core.test_primitives.test_display_rendered_segments_still_join_fully_removed_controls', '5540ae7d4c07b94bb5d658454f89c6ea5d1271aba7c441eb89e1e476e343b0d6'),
    ('nfa-test_display_rendered_segments_still_join_fully_removed_controls-5', 'tests.unit.core.test_primitives.test_display_rendered_segments_still_join_fully_removed_controls', '9d0d7504b571e0ddf7dac0ca523e4e1955bc8a4d16093b0071bbc025d19be363'),
    ('nfa-test_display_rendered_segments_still_join_fully_removed_controls-6', 'tests.unit.core.test_primitives.test_display_rendered_segments_still_join_fully_removed_controls', '2fec4041c277c7983155a31eae4a95b679b30e813c8f738045e7c8a603c83421'),
    ('nfa-test_display_rendered_segments_still_join_fully_removed_controls-7', 'tests.unit.core.test_primitives.test_display_rendered_segments_still_join_fully_removed_controls', 'bc2fad57a24676b5a3eb18dfd2917e3ce954ab515bac54c45d4c5d18821bb03b'),
    ('nfa-test_display_rendered_segments_still_join_fully_removed_controls-8', 'tests.unit.core.test_primitives.test_display_rendered_segments_still_join_fully_removed_controls', 'f8a23f3b99f0024769334cbb866c3b57846febfa8ed3e8d2ab5efbc0ebb647fb'),
    ('nfa-test_display_rendered_segments_still_join_fully_removed_controls-9', 'tests.unit.core.test_primitives.test_display_rendered_segments_still_join_fully_removed_controls', '87510a4a3e1d9bb0f8d362b49d9fae2d05c704b0d18f56854ed4c492942e4178'),
    ('nfa-test_display_rendered_segments_still_join_fully_removed_controls-10', 'tests.unit.core.test_primitives.test_display_rendered_segments_still_join_fully_removed_controls', '6b69d4c17a42f5d259efc53d5ed5bf8a36ab000da7762e24cee184b83381196d'),
    ('nfa-test_display_rendered_segments_still_join_fully_removed_controls-11', 'tests.unit.core.test_primitives.test_display_rendered_segments_still_join_fully_removed_controls', 'd9b431f99ec29db712cfd2b34f2c2fad34fc0d3a4b419675becb0aee571ebe05'),
    ('nfa-test_display_rendered_segments_still_join_fully_removed_controls-12', 'tests.unit.core.test_primitives.test_display_rendered_segments_still_join_fully_removed_controls', 'b14a7f7eeb086dfe9e519ccaef5bfa395bf800fbd30c9c07def811b8a488e62b'),
    ('nfa-test_display_rendered_segments_still_join_fully_removed_controls-13', 'tests.unit.core.test_primitives.test_display_rendered_segments_still_join_fully_removed_controls', '01b70f8f1608b441353f0f78ec94bd2e4d63fc297e720a3d793ad5d5d7691d9e'),
    ('nfa-test_display_rendered_segments_still_join_fully_removed_controls-14', 'tests.unit.core.test_primitives.test_display_rendered_segments_still_join_fully_removed_controls', 'af48d2d9e78f64789a92dbfd309a1d98cc30bfc9f2f85dcfa52aa78595674deb'),
    ('nfa-test_display_rendered_segments_still_join_fully_removed_controls-15', 'tests.unit.core.test_primitives.test_display_rendered_segments_still_join_fully_removed_controls', '8d557b0bfa7f45ed86ba478941a2df8bd1c408ed6e72d667ca73333aa69c144f'),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-0', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', 'a7347cb02ba432ad5134bd9a1d33186c004e7fbc7908ad4380b3af70b64f6b5e'),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-1', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', '104b4bc1a0c99bcb32189df90328e1e7b753d3261f7d4ebc30d35ffbdd457832'),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-2', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', '9e78da6b8bd00f37022e7a3455f6fc821ddfc78ff203173d438b23f3034c63ab'),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-3', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', 'a76a0734a1299ca18552317729ca0a41dbf1a8edce9cbb8f736f75db8f5be813'),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-4', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', '8e1ae2f1ab58d5f3cf7d2971a806cc7e67b3cb98914eb6572aed0d730a015363'),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-5', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', '66e9f0632b8be3403c11f4062f6e55facca9ca6f13f91158df39d917cc4a0940'),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-6', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', 'c13be0edfd565d7492903d728399c65d3953f669960a96dd65e09e0dfb1c0d6f'),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-7', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', 'f144f32d52295bf5a7e312eb9efad8db207d403ae37284248a21e1b1f47bdb07'),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-8', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', '07e0962e84989f0318586643da84eaf7813f36d5d3328ef93b190c4116f00a59'),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-9', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', '7cb379de2772e02bfe317f4ebdd708d1859f1e17569d0e5a9d30026aa9b23c35'),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-10', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', 'a364b5990ad9c2e22ab730b5516239aa59232821cb8658c68d1c65a61a1391d4'),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-11', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', '653a8c521f2370117aa668415b4c119ab43c97b01f3319e0fe07106398e40c88'),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-12', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', 'edb594f97881a3598b1018b2ed80a854c8b6b41e0b5da8402fc57177648ef8a5'),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-13', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', '3051eb285636975fc2d11b41c06ee1b3b863b708d8f6829fed4e6b0c561527a9'),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-14', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', '16f5f306af7ae4f5a97d3bad2985047ead73fd88d6fd7290611f63e03e6d52cc'),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-15', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', '9fd284f11f4a09c5d116edf208be6c26f29bf0ac23f819cb7b0c4c677c067e43'),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-16', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', '16a465c6e5d790441224c9672c2f1aeb1c45e345fde59b80259c702d1610f97e'),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-17', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', 'fa67b8339b5437eb8d1bccae62c1ee6a414dc310dc56966867b4ca8927ebd560'),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-18', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', '86c815813f02b889eef406952f8ee694c42abe58e7def2aadb8f61a2b7b9147a'),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-19', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', '909a437ec8b2c09ffe58febc0fab4a6148180c539faae62303efb8b46a1da431'),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-20', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', '98472eb56291d32356168dd0d558b21119fa1356c728d3930a9e53da983cad23'),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-21', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', '2b42d201f3a54d83317c9c9d996b012b3f68dcc98bc00b81056d346df108b6d8'),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-22', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', '75d7b18bf267f9e3ce94311c9e5ebf893669ee3b3e19144476e55ae63c753338'),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-23', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', 'ea4c8f045a3e109ded9b8cf27926789c8f421ce9dc7df69232e2f0b8f76c091a'),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-24', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', '81388b75650f49589ba32ab759e8914651b0d35f15f2d19c5d5f2a801e079393'),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-25', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', 'fd7b4876c242679c8f856cce2c9a9c74e130523aa05f1de2851811827e556632'),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-26', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', '0bf2ca4f8334f7151813020a31f3198d3650a42f7ea9b909477a71b9cfe06128'),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-27', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', 'd62b79640df884065b82127d2881484f01a50be71e81c607342521640629ac80'),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-28', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', '4d72bb867174e4a30c13f048139b77ad8b73cf0fad6c23302905e3dc8db70e38'),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-29', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', '171bdfba173e3e6cf50524db8902e8df38eaefb5888b423b2e85b3025ef465c4'),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-30', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', '3c6b204bbb880c3bf7df6aa1e407698188423a7dc07641abafeeab5c72abb011'),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-31', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', '0feef922b61b42adc1d0ea9f446f451dd4098ff95be568fc7d73d04cbf77b057'),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-32', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', '51d7d28e84fa2cba2bd1cbb113d458244cb259936503c8a1fb0485a9f258ffe4'),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-33', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', 'e867a73c0b90445c64325477c4ed68ad45f087101680197e69d37cb96e488f5d'),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-34', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', '8322364b18bcbe7cbdec2f5a7d5592abb90f0b8c1df81f9dcb84336c4b8391b0'),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-35', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', '6c6762766a13f518db7541a8dc857eb9b6b8ad9763e59c0ada99b3b9c6ce2b59'),
    ('nfa-test_display_renderer_provenance_recovers_consumed_credential_label-0', 'tests.unit.core.test_primitives.test_display_renderer_provenance_recovers_consumed_credential_label', '2ff5ac077c26be74c0dcf01ce66cb8134d4300d055390986ccb7da388733bc57'),
    ('nfa-test_display_renderer_provenance_recovers_consumed_credential_label-1', 'tests.unit.core.test_primitives.test_display_renderer_provenance_recovers_consumed_credential_label', 'f2b21dcbcac2a5b21ba08bbafdf6ec0e364745d4785f3f6504d30a7dc768c170'),
    ('nfa-test_display_renderer_provenance_recovers_consumed_credential_label-2', 'tests.unit.core.test_primitives.test_display_renderer_provenance_recovers_consumed_credential_label', 'dd53b0dbd430817b1b05332ac9ae8b6012ada9120c441ddfbddc2694c4ab38d2'),
    ('nfa-test_display_renderer_provenance_recovers_consumed_credential_label-3', 'tests.unit.core.test_primitives.test_display_renderer_provenance_recovers_consumed_credential_label', '4033eb75823da5798536f8a38c6a8cd22ab836cb8d2d4c2e82984990ddc1f3b1'),
    ('nfa-test_display_restored_union_masks_before_boundary_changes_or_clipping-0', 'tests.unit.core.test_primitives.test_display_restored_union_masks_before_boundary_changes_or_clipping', 'f22746d9400d6218f58423e50dac3292ef0e846631d835ec7bf18b65bb43e0ce'),
    ('nfa-test_display_restored_union_masks_before_boundary_changes_or_clipping-1', 'tests.unit.core.test_primitives.test_display_restored_union_masks_before_boundary_changes_or_clipping', 'fda1ad7987e7db872f97b5d3c0369e6632d81d88176231d2fe0d9e0548cafb89'),
    ('nfa-test_display_restored_union_masks_before_boundary_changes_or_clipping-2', 'tests.unit.core.test_primitives.test_display_restored_union_masks_before_boundary_changes_or_clipping', '7856625ced6b67b63a20a9c39b829f7cefe8680f49668f3b0a407a54b55ec4a6'),
    ('nfa-test_display_restored_union_masks_before_boundary_changes_or_clipping-3', 'tests.unit.core.test_primitives.test_display_restored_union_masks_before_boundary_changes_or_clipping', '7ac9933fe9793b0f6b541a03900c78e409253b9188ad4804c1cd2994430a525f'),
    ('nfa-test_display_restored_union_masks_before_boundary_changes_or_clipping-4', 'tests.unit.core.test_primitives.test_display_restored_union_masks_before_boundary_changes_or_clipping', 'f0a4a572d10f652bf5e3cd5b0f75730085a8bb8e41a940a0764a7c1420b6abd5'),
    ('nfa-test_display_restored_union_masks_before_boundary_changes_or_clipping-5', 'tests.unit.core.test_primitives.test_display_restored_union_masks_before_boundary_changes_or_clipping', '4b510e1f958cf91a563876b68af3ef5bd184cf3b298eb3f2ec103606cedd6fc1'),
    ('nfa-test_display_restored_union_masks_before_boundary_changes_or_clipping-6', 'tests.unit.core.test_primitives.test_display_restored_union_masks_before_boundary_changes_or_clipping', '97ca75e615e508589783a4f65d97ae396345355ab956d223ad1f6733378466d0'),
    ('nfa-test_display_restored_union_masks_before_boundary_changes_or_clipping-7', 'tests.unit.core.test_primitives.test_display_restored_union_masks_before_boundary_changes_or_clipping', 'de8882ad107fabec3382cefd3c7bd3387c91562fb12ae75b41180fee7a7ccf38'),
    ('nfa-test_display_restored_union_masks_before_boundary_changes_or_clipping-8', 'tests.unit.core.test_primitives.test_display_restored_union_masks_before_boundary_changes_or_clipping', 'bfa0b1f3053df3e28777e1f0bf30a729e5bb0f5802b7e5e55cf40afcfad2ac1e'),
    ('nfa-test_display_restored_union_masks_before_boundary_changes_or_clipping-9', 'tests.unit.core.test_primitives.test_display_restored_union_masks_before_boundary_changes_or_clipping', 'bb755e37a6636a354a69ced7cdd49adb205d2c51300fb3cc8664008943c02898'),
    ('nfa-test_display_restored_union_masks_before_boundary_changes_or_clipping-10', 'tests.unit.core.test_primitives.test_display_restored_union_masks_before_boundary_changes_or_clipping', 'eab64ae23c28d01735b4c0d3a5cc302d5d5141f4c41efd0114481805b58f2e07'),
    ('nfa-test_display_restored_union_masks_before_boundary_changes_or_clipping-11', 'tests.unit.core.test_primitives.test_display_restored_union_masks_before_boundary_changes_or_clipping', 'ef01ed5deaab26a99bcffd96855fad08acf9507c388169ec938fd3436e91a198'),
    ('nfa-test_display_source_guard_cannot_complete_a_new_credential_or_tear_a_mask-0', 'tests.unit.core.test_primitives.test_display_source_guard_cannot_complete_a_new_credential_or_tear_a_mask', '2ff5ac077c26be74c0dcf01ce66cb8134d4300d055390986ccb7da388733bc57'),
    ('nfa-test_display_source_guard_cannot_complete_a_new_credential_or_tear_a_mask-1', 'tests.unit.core.test_primitives.test_display_source_guard_cannot_complete_a_new_credential_or_tear_a_mask', 'f2b21dcbcac2a5b21ba08bbafdf6ec0e364745d4785f3f6504d30a7dc768c170'),
    ('nfa-test_display_source_guard_cannot_complete_a_new_credential_or_tear_a_mask-2', 'tests.unit.core.test_primitives.test_display_source_guard_cannot_complete_a_new_credential_or_tear_a_mask', 'dd53b0dbd430817b1b05332ac9ae8b6012ada9120c441ddfbddc2694c4ab38d2'),
    ('nfa-test_display_source_guard_cannot_complete_a_new_credential_or_tear_a_mask-3', 'tests.unit.core.test_primitives.test_display_source_guard_cannot_complete_a_new_credential_or_tear_a_mask', '4033eb75823da5798536f8a38c6a8cd22ab836cb8d2d4c2e82984990ddc1f3b1'),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-0', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', 'b9a099768b15f3a65360bcafc0bf22c5a9b8e2a73f5f73fb7270ea58af4dcd9b'),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-1', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', '1294b54f51a6051beff4ab5c5852ef993db2b9760e8478966c37c151833705a2'),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-2', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', 'c8335429a9cce9c95bafa5a83272b7811806954db5084669fd5c7da9ce9c0705'),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-3', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', 'efac0cd71ebb8eddd1016f8ffd1769f0c0f55949556539355ca6314f60b10231'),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-4', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', 'ba24b47ccf4759650d1cd0dd08b39ec7b6560b26360eea3188283d521cdc6555'),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-5', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', '8d38334bf1a5f34ae14b0ae1b1211f1647c120e53d1b7885b680badb26e063ce'),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-6', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', '02157a3d08c95b4a777c66702e273907be8e7acede090141ccd30cf2869ff9ea'),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-7', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', '6ecdde3423cca5c1bf16b1da5970b3472dc4fa4fe062748d1395722c4d2f371f'),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-8', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', '30cb2379c1c33bb01d57cc2cf346842130dfa14e0d2a4508503e41b320357d08'),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-9', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', 'e341079d70654068e9c70409aacc7af197891aa612fe26dba88f3c933e958a32'),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-10', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', '7a690e8143dd4b7520ff2eaca882d648a21345a5ede0118def1551302ccde9b6'),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-11', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', '5d161d36edd748288b7d83815bba8e4dfd4e1535ee6fb6850180dd475759f0c0'),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-12', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', '91305d19742b7afede01b3acf56b434c6417f74b0cb55a9068ef0c7dfc1cd19a'),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-13', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', '1a59dc678944e71579351f69a110d15c7c96a455e33dfb4fa66fb452c387f7f5'),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-14', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', '80ff0b9fa80dc3ea850f6e930ead0bbfd40a9ed34439797926de41a9239eb21a'),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-15', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', 'caa7906b3f4911d4de850d4d56e5c062acd72a5084f28278b7138d74e7816586'),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-16', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', 'f9512ae0cd10c1a47bd6e3082ea0dea735946b1e4c15e7aecb2a900fb3ff8c56'),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-17', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', 'e1ff096ad9d2f76f3f3a61bb4563af50a30854053422c056444120fe93c1df96'),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-18', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', '218eef081cddc5d891874c845556799c66430de9fe75d69a7834574fbfea32b4'),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-19', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', 'cc124925570a48b266854deaea0ff8798fe06e93ba591b720be7d15148388628'),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-20', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', 'dee175974e155fcf9fd906b39ac873626db16b4a4d1129d6cb4a5b37f8eb1451'),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-21', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', '12d00491c2d38eb92592e505dc5b13cd2880cd22e431ed54b8003f24c21cd46c'),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-22', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', '431489582fe75b6dd5a9855f1acdcd2c525ca7e4efbd42ddd09b0473c19e74b3'),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-23', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', '3441634175307034d2c6987acaddcf516dcb500d33bff3a904dd684d4b4ebe15'),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-24', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', '8e565c0af0704c0737eda9d36e2b49a0c6e22a41fcd17350c2ff743ab0960270'),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-25', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', '091ce7c4c5a648660ecdb2accd4b685d44d148fd99abb17c23e61a94b9c312c9'),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-26', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', '48e21e3140f6c408de58ef2f60f7c365f6cbdf08e512e2e43c15028ef569761a'),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-27', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', 'b181960b422bedc9bef44db41eea9918ec3249490d88b41753d7a8bfab8f130a'),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-28', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', '45f5a3f8ead2223b4647366421a1d9603a11bc348eb1c0705c9a3533ef353465'),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-29', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', 'a9bdec6dd9188f1d652e995916aebe35df2f6bf6e985e8bf7dcbd0d140e8e7c6'),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-30', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', 'b2cd744371a920edea9f337c3a91f3fd76b0643d863aea34ef65ecfdd8794ac4'),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-31', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', '7874d8881c13c47804f0a558744279f6118ccf63dd7eafce2a47c1a58e68740a'),
    ('nfa-test_display_source_segments_do_not_join_visible_context_through_hidden_payload-0', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_join_visible_context_through_hidden_payload', '4251e6d450880a59b7a5ba3ea9c5a10827ec70ebf3d6b2e512feddc2b6da4e08'),
    ('nfa-test_display_source_segments_do_not_join_visible_context_through_hidden_payload-1', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_join_visible_context_through_hidden_payload', 'e10efb592c9c193c7fe70f0f0db9e62a5a73b0dfc1c6e5819da42133ab53fc5b'),
    ('nfa-test_display_source_segments_do_not_join_visible_context_through_hidden_payload-2', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_join_visible_context_through_hidden_payload', 'a40faa7b2013d8e73db6f2dc1b400cf770559c75e0fdd8534df3fa70250a368d'),
    ('nfa-test_display_source_segments_do_not_join_visible_context_through_hidden_payload-3', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_join_visible_context_through_hidden_payload', '6231717d040e947bb9133c9244c70394401ce7f22b4b9265c0353b237e746f54'),
    ('nfa-test_display_source_segments_do_not_join_visible_context_through_hidden_payload-4', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_join_visible_context_through_hidden_payload', '5ebde6290d5dd265b451f370d7a4b0431e9e8c52190445d8da1a1893391221c9'),
    ('nfa-test_display_source_segments_do_not_join_visible_context_through_hidden_payload-5', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_join_visible_context_through_hidden_payload', '44b7dbb0c8a0463f317397e9324a9467e282523d77a77d05e30cc880f538da82'),
    ('nfa-test_display_source_segments_do_not_join_visible_context_through_hidden_payload-6', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_join_visible_context_through_hidden_payload', '7eaefe572dffb8c48f3d100c0c852e74cc607b07e9cfbbecba21c28432015a98'),
    ('nfa-test_display_source_segments_do_not_join_visible_context_through_hidden_payload-7', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_join_visible_context_through_hidden_payload', '96db07d3bb9e8de0b214bce5548a34a80de98d1b18ed047e15fea95f02a029de'),
    ('nfa-test_display_source_segments_do_not_join_visible_context_through_hidden_payload-8', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_join_visible_context_through_hidden_payload', 'e24d2003fedfcd29d08814ddf7802ec8b6ed1e3cd681fb0fea1d0678ade010a9'),
    ('nfa-test_display_source_segments_do_not_join_visible_context_through_hidden_payload-9', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_join_visible_context_through_hidden_payload', 'ae969bedfbebdab096186dae537a4598e2ac5fb99e117deaa2e53dd54fec7476'),
    ('nfa-test_display_source_segments_do_not_join_visible_context_through_hidden_payload-10', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_join_visible_context_through_hidden_payload', '187647fa3df9c00feb7346d671098745b9c960410fbc523b3943090189e9dacf'),
    ('nfa-test_display_source_segments_do_not_join_visible_context_through_hidden_payload-11', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_join_visible_context_through_hidden_payload', '2109e21f5575bbdcc8b36a81bdba3656e81f4363131cea862961ba8808fea814'),
    ('nfa-test_display_source_segments_do_not_join_visible_context_through_hidden_payload-12', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_join_visible_context_through_hidden_payload', 'cca8e1f6015845d8f59234113dd72f7620a807188f387228eb8b1b7dd0ccfef3'),
    ('nfa-test_display_source_segments_do_not_join_visible_context_through_hidden_payload-13', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_join_visible_context_through_hidden_payload', '012b7f351afda8504767ab592c32604840be6fc5c2d4933fc0c02cb7aff278e9'),
    ('nfa-test_display_source_segments_do_not_join_visible_context_through_hidden_payload-14', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_join_visible_context_through_hidden_payload', '2f32845c9e31f3519994536cb12440f1ef754ad42c9cbb0038bbbd6989da11a2'),
    ('nfa-test_display_source_segments_do_not_join_visible_context_through_hidden_payload-15', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_join_visible_context_through_hidden_payload', 'fe7ab13d202a3323e6a1f035b9a17b429f8e05fd1414b4625374f5093ee5323f'),
    ('nfa-test_display_source_segments_keep_prefixed_secret_context_detectable-0', 'tests.unit.core.test_primitives.test_display_source_segments_keep_prefixed_secret_context_detectable', 'e8afd38a5f3b014b4fb3d44f9dc7c7eea93fdc5a81d2bdea0dc616afa48f4f8a'),
    ('nfa-test_display_source_segments_keep_prefixed_secret_context_detectable-1', 'tests.unit.core.test_primitives.test_display_source_segments_keep_prefixed_secret_context_detectable', '827515e8c04c03c866626ccffbc63fe9029128a0ae02e66180907dbcbc8f9011'),
    ('nfa-test_display_source_segments_keep_prefixed_secret_context_detectable-2', 'tests.unit.core.test_primitives.test_display_source_segments_keep_prefixed_secret_context_detectable', 'ba214fc2a37a85ec205d3b24113e7a6777eec439b852dfef5f971a48fd34cbc2'),
    ('nfa-test_display_source_segments_keep_prefixed_secret_context_detectable-3', 'tests.unit.core.test_primitives.test_display_source_segments_keep_prefixed_secret_context_detectable', '3072a5e2c4eea0a13e4868f2f0c690373cf892b5fd82a24d8c22cdeb7fb8b815'),
    ('nfa-test_display_source_segments_keep_prefixed_secret_context_detectable-4', 'tests.unit.core.test_primitives.test_display_source_segments_keep_prefixed_secret_context_detectable', '3b2fe4802f75b67ac7bcaa2746748ea02948307f7318f8065f0d1d70c1482dec'),
    ('nfa-test_display_source_segments_keep_prefixed_secret_context_detectable-5', 'tests.unit.core.test_primitives.test_display_source_segments_keep_prefixed_secret_context_detectable', 'ad0581f04076e9a7661014e9874bfc764aa6188bddbc1f8199326b4b0a58fa57'),
    ('nfa-test_display_source_segments_keep_prefixed_secret_context_detectable-6', 'tests.unit.core.test_primitives.test_display_source_segments_keep_prefixed_secret_context_detectable', '376147c5d8d21eee10b44ee263e26a6783ac99872d89ee67b5def0a15ae20403'),
    ('nfa-test_display_source_segments_keep_prefixed_secret_context_detectable-7', 'tests.unit.core.test_primitives.test_display_source_segments_keep_prefixed_secret_context_detectable', '9c4bc2df131783b959bef855d271d3df55b020b8c742dd9d375c4ce76380084f'),
    ('nfa-test_display_source_segments_keep_prefixed_secret_context_detectable-8', 'tests.unit.core.test_primitives.test_display_source_segments_keep_prefixed_secret_context_detectable', '81921371d8a61104befed2275cfa5e048f7cc52330fa28d14db01008715ba7d1'),
    ('nfa-test_display_source_segments_keep_prefixed_secret_context_detectable-9', 'tests.unit.core.test_primitives.test_display_source_segments_keep_prefixed_secret_context_detectable', '443f4dfd2d1652781a1b60e01bc00dc7712d6dc0588979bfe070031e0108d32d'),
    ('nfa-test_display_source_segments_keep_prefixed_secret_context_detectable-10', 'tests.unit.core.test_primitives.test_display_source_segments_keep_prefixed_secret_context_detectable', '8a9694cbdedb1f2ab8a064eab366f55c5b7ec854f3cc20ca421a393afab77534'),
    ('nfa-test_display_source_segments_keep_prefixed_secret_context_detectable-11', 'tests.unit.core.test_primitives.test_display_source_segments_keep_prefixed_secret_context_detectable', '2f851651ee7808a9cc8e1ff3c526453991d5aa1516fc161ceed27d1a3f98916e'),
    ('nfa-test_display_source_segments_seal_suppressed_strings-0', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', 'de0322fdd91c74708184266b532a425045bfd4798f6c0b016634228d4a089cfa'),
    ('nfa-test_display_source_segments_seal_suppressed_strings-1', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', '695157e259e94dc0cfd228ed266efaff9d4f0d9b787ac2fe294a769b050df538'),
    ('nfa-test_display_source_segments_seal_suppressed_strings-2', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', 'ce61dd12bfd4e898393762da2170844a99024e248f9d38512d742eced27f7094'),
    ('nfa-test_display_source_segments_seal_suppressed_strings-3', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', '0c6e060d4ced8e29b352b25edb2408cacb1c7ab9dbfc78fe63d66a3bdb29d2de'),
    ('nfa-test_display_source_segments_seal_suppressed_strings-4', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', 'ac3307e12a06548f222cc16ca945f92d8a8dc7dc2cb6aa072f95d62b2926f7ce'),
    ('nfa-test_display_source_segments_seal_suppressed_strings-5', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', '36568d689810f95e648eb20b0d719bc76b4daa7a9d14c042c705d2806678db84'),
    ('nfa-test_display_source_segments_seal_suppressed_strings-6', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', '88084b6730a269db0e84a8b40763905b8181f0c2b4652e5baa1453a676176744'),
    ('nfa-test_display_source_segments_seal_suppressed_strings-7', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', 'f97502274303cf00452f30cecdbfd324fd2ff654aaad0aeea5e4491abdd0643f'),
    ('nfa-test_display_source_segments_seal_suppressed_strings-8', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', '9d127bd2fdc8dd30b229225fc9b87ef8c0914f0fc6f5751be0c5a6aac896f5ca'),
    ('nfa-test_display_source_segments_seal_suppressed_strings-9', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', '784f3c608a7e1e7ef2ec5742d6cf4305cf37d25e45a8b0449de4eabed2bd5c37'),
    ('nfa-test_display_source_segments_seal_suppressed_strings-10', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', '71ccb5e4747e2525cdc112cd88944048d671ef23ca3a5dcc384149237691e3d4'),
    ('nfa-test_display_source_segments_seal_suppressed_strings-11', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', 'b3f0eaaa9fae5649426c5e4e02400351c9173cb605f076fee3941bd280a1408a'),
    ('nfa-test_display_source_segments_seal_suppressed_strings-12', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', '9303144e80ecd569c562b847cd5619e587c51dd6d9f2405d319a98b1aa093bf8'),
    ('nfa-test_display_source_segments_seal_suppressed_strings-13', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', 'dc10abb13aea523987bb03617367a7ebd766aa2dd4b53e59a1da1ed4ef1d3345'),
    ('nfa-test_display_source_segments_seal_suppressed_strings-14', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', '0d82f863505d6126869489b0599750828b8cabd6c5c5e0f1164675cc5362d234'),
    ('nfa-test_display_source_segments_seal_suppressed_strings-15', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', '9ca8ae511e8308b2be910f89c82f7c0741e49aefcc182537a21f80cebef338ca'),
    ('nfa-test_display_source_segments_seal_suppressed_strings-16', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', '652cf048b4fee250ed8f1abd16c218d3aae8565a6d87d9210019eb0b0676c505'),
    ('nfa-test_display_source_segments_seal_suppressed_strings-17', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', 'feddde978ca7aa747eda1002a55daa3d815734291f1fd69793c068ebe781456d'),
    ('nfa-test_display_source_segments_seal_suppressed_strings-18', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', 'fba9bd606a476b0549ea84a27c33e529d0466d856bff5405d356f59ae0650225'),
    ('nfa-test_display_source_segments_seal_suppressed_strings-19', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', 'da496a32b9b986c0ac972a8ff940f75d61bad1c1642c4f28cfc4b7032211b8ec'),
    ('nfa-test_display_source_segments_seal_suppressed_strings-20', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', 'c4f028e23874f67d4cba9f0c1752681c5c8bb304de226406b4c7f119d363dd58'),
    ('nfa-test_display_source_segments_seal_suppressed_strings-21', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', 'c35e2f9066e7091ef9b59c9bd10bc9db215a2fe6443acaacf101380fc8823b39'),
    ('nfa-test_display_source_segments_seal_suppressed_strings-22', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', '63e7f9df0e1e2c90ce5fe4fe3bd037e0d478ddea9c62aa7001ed27f2dc657100'),
    ('nfa-test_display_source_segments_seal_suppressed_strings-23', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', 'b9a116156a27b55161bb01f88fa168a3b39af38f16c48244e36742a17d8245ee'),
    ('nfa-test_display_source_segments_seal_suppressed_strings-24', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', '266c79b3db7aec98f5807c0908d4ff584cc3feef54252a0b2bf2752b2caa8b5e'),
    ('nfa-test_display_source_segments_seal_suppressed_strings-25', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', 'c8d64e4948138fb8b8ab7fb0ccdd2bf41cbd8f0aaf35ee4bd9eb800d7672cc33'),
    ('nfa-test_display_source_segments_seal_suppressed_strings-26', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', '7d150f4d0c25839e145b2b71e771f6e91ec5559bcd0804b3290358d03d83770e'),
    ('nfa-test_display_source_segments_seal_suppressed_strings-27', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', 'e8f5916b27c3c6d7af869df29f4f6af71c775953a40b417f9008f7c8ab95f227'),
    ('nfa-test_display_source_segments_seal_suppressed_strings-28', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', '12476d27de72d5567a845936d3484bcf54b030642b92703ccc43913994dc885b'),
    ('nfa-test_display_source_segments_seal_suppressed_strings-29', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', '31c371a5336fa435138273459047f46ff2080bb2e8cb36679a03947f3d61e77c'),
    ('nfa-test_display_source_segments_seal_suppressed_strings-30', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', '4e96d9b5950d343303a33415158e7284e51fb2896579e5f2c5ab1647a0aeeb74'),
    ('nfa-test_display_source_segments_seal_suppressed_strings-31', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', '942c08b84df11dd7683da22a98a3e1e716a57b17b2818cafe74fb21e9dc12034'),
    ('nfa-test_display_source_segments_seal_suppressed_strings-32', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', '579546ab5792140e678a0ba170fe4fcd5fba9d0831edf7515104c7e2c0e9e3b8'),
    ('nfa-test_display_source_segments_seal_suppressed_strings-33', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', '5390f59ab76026303658c1b7547f9d5e4cf411da4df3cd329a30574c4ea30c14'),
    ('nfa-test_display_source_segments_seal_suppressed_strings-34', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', '253faf452071b3dfdfe9334f0d91c568a242d8c0cde75fec429adba95acf6259'),
    ('nfa-test_display_source_segments_seal_suppressed_strings-35', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', '22ecf39f6cdfbf9662fd1c13cc278abec999c3d4f8d5ba781166a870acadd7f9'),
    ('nfa-test_display_source_segments_seal_suppressed_strings-36', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', '4f38446198cf2419c715820658850e6e4d27340c125d8d86328c5b1de708b422'),
    ('nfa-test_display_source_segments_seal_suppressed_strings-37', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', 'edd6fd9baad9b80a54f7d3d861599dcb425a5c1aa420e08cc926e1d0905f3ce6'),
    ('nfa-test_display_source_segments_seal_suppressed_strings-38', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', '78d33a48ec71e23fa689cd76ee1349df4eabe634b06db8ed7972b5d3054c08ed'),
    ('nfa-test_display_source_segments_seal_suppressed_strings-39', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', '1374909392b38e4461ba138b82d7e6618140ca576a02c7c52c3401e2255abf74'),
    ('nfa-test_display_source_segments_seal_suppressed_strings-40', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', 'bcfcaf54839c5c6f5bf3fcdcd738a59f338f88a31862faeaf7888b336326c4c5'),
    ('nfa-test_display_source_segments_seal_suppressed_strings-41', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', '7750017f09e261beb30997ca2029b790b45af1a558247dd553afbe1132214284'),
    ('nfa-test_display_source_segments_seal_suppressed_strings-42', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', '057c0751bb6a65edd3ebb6e67296bd4a3c49addb1e1087c56ed476d6ae7ae229'),
    ('nfa-test_display_source_segments_seal_suppressed_strings-43', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', '3666e1dc7a41e3f8c7a06087e75e002de7dab361eb394a05c0f123e9bc0f0a8c'),
    ('nfa-test_display_source_segments_seal_suppressed_strings-44', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', 'b4565f62b8322918f0a31a249a4f0e19c0f3fc971db0354ebe06baed86a539d9'),
    ('nfa-test_display_source_segments_seal_suppressed_strings-45', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', 'dd24720f5c196d3917fbce5d9776b3c6b1d4d3d77d200349e1187a94ffe2e539'),
    ('nfa-test_display_source_segments_seal_suppressed_strings-46', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', 'a64dff404f98096beaff8653f2d86886844b70e1a85bddf068745649f67e3f0e'),
    ('nfa-test_display_source_segments_seal_suppressed_strings-47', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', '27f174ae00435aba06169143a6bb52fce0922f264a6d08642e80643a3a1fc722'),
    ('nfa-test_display_source_segments_still_mask_visible_secrets_on_both_sides-0', 'tests.unit.core.test_primitives.test_display_source_segments_still_mask_visible_secrets_on_both_sides', '4251e6d450880a59b7a5ba3ea9c5a10827ec70ebf3d6b2e512feddc2b6da4e08'),
    ('nfa-test_display_source_segments_still_mask_visible_secrets_on_both_sides-1', 'tests.unit.core.test_primitives.test_display_source_segments_still_mask_visible_secrets_on_both_sides', 'e10efb592c9c193c7fe70f0f0db9e62a5a73b0dfc1c6e5819da42133ab53fc5b'),
    ('nfa-test_display_source_segments_still_mask_visible_secrets_on_both_sides-2', 'tests.unit.core.test_primitives.test_display_source_segments_still_mask_visible_secrets_on_both_sides', 'a40faa7b2013d8e73db6f2dc1b400cf770559c75e0fdd8534df3fa70250a368d'),
    ('nfa-test_display_source_segments_still_mask_visible_secrets_on_both_sides-3', 'tests.unit.core.test_primitives.test_display_source_segments_still_mask_visible_secrets_on_both_sides', '6231717d040e947bb9133c9244c70394401ce7f22b4b9265c0353b237e746f54'),
    ('nfa-test_display_source_segments_still_mask_visible_secrets_on_both_sides-4', 'tests.unit.core.test_primitives.test_display_source_segments_still_mask_visible_secrets_on_both_sides', '5ebde6290d5dd265b451f370d7a4b0431e9e8c52190445d8da1a1893391221c9'),
    ('nfa-test_display_source_segments_still_mask_visible_secrets_on_both_sides-5', 'tests.unit.core.test_primitives.test_display_source_segments_still_mask_visible_secrets_on_both_sides', '44b7dbb0c8a0463f317397e9324a9467e282523d77a77d05e30cc880f538da82'),
    ('nfa-test_display_source_segments_still_mask_visible_secrets_on_both_sides-6', 'tests.unit.core.test_primitives.test_display_source_segments_still_mask_visible_secrets_on_both_sides', '7eaefe572dffb8c48f3d100c0c852e74cc607b07e9cfbbecba21c28432015a98'),
    ('nfa-test_display_source_segments_still_mask_visible_secrets_on_both_sides-7', 'tests.unit.core.test_primitives.test_display_source_segments_still_mask_visible_secrets_on_both_sides', '96db07d3bb9e8de0b214bce5548a34a80de98d1b18ed047e15fea95f02a029de'),
    ('nfa-test_display_source_segments_still_mask_visible_secrets_on_both_sides-8', 'tests.unit.core.test_primitives.test_display_source_segments_still_mask_visible_secrets_on_both_sides', 'e24d2003fedfcd29d08814ddf7802ec8b6ed1e3cd681fb0fea1d0678ade010a9'),
    ('nfa-test_display_source_segments_still_mask_visible_secrets_on_both_sides-9', 'tests.unit.core.test_primitives.test_display_source_segments_still_mask_visible_secrets_on_both_sides', 'ae969bedfbebdab096186dae537a4598e2ac5fb99e117deaa2e53dd54fec7476'),
    ('nfa-test_display_source_segments_still_mask_visible_secrets_on_both_sides-10', 'tests.unit.core.test_primitives.test_display_source_segments_still_mask_visible_secrets_on_both_sides', '187647fa3df9c00feb7346d671098745b9c960410fbc523b3943090189e9dacf'),
    ('nfa-test_display_source_segments_still_mask_visible_secrets_on_both_sides-11', 'tests.unit.core.test_primitives.test_display_source_segments_still_mask_visible_secrets_on_both_sides', '2109e21f5575bbdcc8b36a81bdba3656e81f4363131cea862961ba8808fea814'),
    ('nfa-test_display_source_segments_still_mask_visible_secrets_on_both_sides-12', 'tests.unit.core.test_primitives.test_display_source_segments_still_mask_visible_secrets_on_both_sides', 'cca8e1f6015845d8f59234113dd72f7620a807188f387228eb8b1b7dd0ccfef3'),
    ('nfa-test_display_source_segments_still_mask_visible_secrets_on_both_sides-13', 'tests.unit.core.test_primitives.test_display_source_segments_still_mask_visible_secrets_on_both_sides', '012b7f351afda8504767ab592c32604840be6fc5c2d4933fc0c02cb7aff278e9'),
    ('nfa-test_display_source_segments_still_mask_visible_secrets_on_both_sides-14', 'tests.unit.core.test_primitives.test_display_source_segments_still_mask_visible_secrets_on_both_sides', '2f32845c9e31f3519994536cb12440f1ef754ad42c9cbb0038bbbd6989da11a2'),
    ('nfa-test_display_source_segments_still_mask_visible_secrets_on_both_sides-15', 'tests.unit.core.test_primitives.test_display_source_segments_still_mask_visible_secrets_on_both_sides', 'fe7ab13d202a3323e6a1f035b9a17b429f8e05fd1414b4625374f5093ee5323f'),
    ('nfa-test_display_source_view_accepts_control_only_nonsecret_text-0', 'tests.unit.core.test_primitives.test_display_source_view_accepts_control_only_nonsecret_text', 'c4b258d4fa3c1475585d50044afab1077e3d75bdd48ff30fbb7c75017b916f5e'),
    ('nfa-test_display_source_view_accepts_control_only_nonsecret_text-1', 'tests.unit.core.test_primitives.test_display_source_view_accepts_control_only_nonsecret_text', 'bd733988e6d115c534c918ef2d241c09325a19e17ea98a0e5a33fe722f09ab57'),
    ('nfa-test_display_source_view_accepts_control_only_nonsecret_text-2', 'tests.unit.core.test_primitives.test_display_source_view_accepts_control_only_nonsecret_text', '01812389a2b959af87889f22a36a871b52c1b0110282d3aa593b17ada5f4f130'),
    ('nfa-test_display_source_view_bounds_repeated_unterminated_pem_work-0', 'tests.unit.core.test_primitives.test_display_source_view_bounds_repeated_unterminated_pem_work', '44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-0', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '33565636f67c17da4e058a5fb0459d0e578333773ef49fb895ccddf87e09493f'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-1', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '39651bd5a6fd778b4ce8239fe13a2efd9705286233d76708dd31890eae2e4ec9'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-2', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'e3755026785c14b934aa17088f8b2b61f7032ada7f3784e9d8c6e97451178fb5'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-3', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '7a5c1e13a37aaf01fa00ea77eed3973f57d4224cd2f70826eb7e05920772e739'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-4', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '7a19fec96dd4d07994214a58712bde114ebfe7850c5926147ea74f7962244e9c'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-5', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '187f12dcfd7d34ae1a99c2455bcaf64e5c8674d64bd777b7230278d100901f8e'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-6', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'cf308b2003fa181fa577439cf7fc2e78c2105266f0cfc450fa64a2f22d70c526'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-7', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '20c7bffd2f82bf96f2c7038012e8b0c9c6fd26d555d2abf90178a4142aa0fa9f'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-8', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'd67b54b5b683d31c0b99c1e4116b320db9030d1da163f947c479903e84af19c0'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-9', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '95af3ef1a85e2984b3b916afe3d15265d904e04490d94e893022cd2a67828f99'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-10', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '21451502bf50f5536b0a6dc876bf6950a1450df8ac465a7a93f6ba95d360e555'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-11', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '74a88a1a20c8033fbb327c61b29a77a5a0967dd24ba54ebf0c22c8d9b3ab18cc'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-12', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '861f946ac3201863f8e8938bbeb77eaeaf86c3614b815381dcc688b69ff39a27'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-13', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '962a6ca1d0b2ad6974313b9005f9dbad7d088a5c0823bb4f03ffc3f5b4413a93'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-14', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'b1a447df6affb954cec7560ed204efd5f2521381e40c5e77198902e7dcb7363e'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-15', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'ab0ffbbbc4272aa3c9fcb0511511c8995a2c759f57ad9d8fd676b51a2b7172e3'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-16', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '0aadba728b69ee9e72e5e5735cbafeb440be6567f8d7dac263f54a6e4e9a29e6'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-17', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '1baa68f0d4d931797202f42e404e9aa51d41e7bebb3ebb8eb15552e9912dea8d'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-18', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'b1ef0650c522ec62e6ff59529cb6fcc4e152922c2b324879947941a4484d3e7c'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-19', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '89d9abfde7fddec6203b584a1516ff2abd60225c0e510d5ecaa32ced2462f55b'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-20', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '439399e9453d27fba3832061d683d5d9bfa4a49d0bb04b2e1388747703b8ce81'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-21', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'f8bc49aa5a0f9f89e7beb246f18045eef45d246f2a65de580d08093ead8f32b7'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-22', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '2e9a1ad12b56c20322889ad818f1e6c91e7233408736e884ff56d28792eb5fde'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-23', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'f9d937fda1a8cffc4f339ec6203146735e1aa4143a9b0b9b9628e9c2bf70fb25'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-24', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '838ce0d88e582ceb636274d5234d37c4acefaa40c2eb3d0b234770c1c46a4545'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-25', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'f60a8cc3f8ef8547059a7bfee16627b0edaa050f1bbf767d12ad768a5845b1e5'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-26', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '2882705f1bad63ef19a97d5889dfa912f6f5a95cce9458469a1263dc678ca464'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-27', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'ae37f6109699f030ae66c64d83ae379e4ac2c9b79aa48b417ae3855f41f630fe'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-28', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '2492561337e9cbf1a9b60a39865c76c0d5f9a9525ca6fcb12f46547837556068'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-29', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '658db61826eaf04d0fd03ec816d94fda8d7e885c8f67b6614e25eef12b91c05d'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-30', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '392a77a91fe3325e678c03ac61f5c579845aeff7e5905facb69ecc6c452205f9'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-31', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '7400ef28af376cbaf05d089d5a48a69d5f4b6f1efca10673e9a67698569440a9'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-32', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'd3246bf1ecfc265577adf85beabf2151b54867374c08593deeeb1e4489261190'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-33', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'dce84db613c8bbc7d731fbf32dd3e88a2841e956546e8a4bff761a1e222157ff'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-34', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '59a5c4fd8e43f7ea476ac963a64eb9c38e5cbd6ef0b4c3e8f9d73fcdcdd1a060'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-35', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'a34eacb5b4e27b048775fc0a410ef6280d1561a2969107504113992e5a20e932'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-36', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '92abb7530764ffd5f1671cbf963c428bb07d6a1d1d883b3c83d328db0c0d47ba'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-37', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '94885510ec06ea773da658f6fc3dbac3de1565f95bdb95e6b85e17be87f69958'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-38', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '5aa31910ae099fe1d15ae795a08a4cdbc411ed489ca4010323520bae707f9d9e'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-39', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'f41e25b9f033c0caeb53b1fa9e32c41398d6090e1222389fb63a790e3359114a'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-40', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'aa58e7a8aa8b8b558c71a5807eac50ffddeb9137f2bd74be624f9c52b0945d9c'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-41', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '8403931ad5388d1a5b86dba079bf31be0df6acf2818facf33d46a0350c55608d'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-42', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '17b49fc3fef1de9ca71d1c94c55e3cb404f9720aea6aa664391ea9310d0bd0e5'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-43', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '42f5fd1b1d3ff67a7953312e57e046d0ad33ecaf8776878df3046b45fa7b19c0'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-44', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'b72ca128a7ca893d70c667e90bb3fc2239817728858f0e2c637045e268d94384'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-45', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '363aafe8332a3418ee1d43f8d928c6144192ce2404d3450f96e28d742b3040ce'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-46', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '29233e353b0bfb33e3ffc212448f7ca94716f9cc88f5d4af6c00dd315ce91543'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-47', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '067becb80d8ff3ed435c030a75c0f2509cee31ba3df972b43b952ce28bff7cd5'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-48', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'ab6280f4149d1859a80a319b9947478800ea9414a58e33f84b18c25ef57186c3'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-49', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '77d5d5e3cf5b27b53673dea5b85a03e489704de8a8624351cb6be14d1344ddbb'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-50', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '105a5b515a2db48802a48a6980165ab961ed04d7c3aaca07c7be91fac2174766'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-51', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '40e493d3f698cca0dacf255b0a0ce00958f82be77adcfe8e0b4940811e02c807'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-52', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '377b4a95b2c6fab5c6d83026dbf89fbe2f515837ce7f5438e8519e7d00be32dd'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-53', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '57910ae8f8c189938915217233d5513751e7d83ccdd8cf6bbc43214a938ec22e'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-54', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '599e46fa74041601f3b5819e412d9232c7b3b8e1d17a1f552436663b3fdd36e6'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-55', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '6a784d7b727cb36c6b4d27b2ace13977092f6f28af24c20af506593484a96b93'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-56', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '78245fd250de5c293a233b31629a3487f90fa366ce7e6da2cc74c102b1ae5941'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-57', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '6db7ac781d72e46be2a411213a0131a56d04b57637811cf5660659353a338385'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-58', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '16f0ed8bcd220c5f0598bc0e73c555a226a1bf01c29214c4afcd5aaff912d9bb'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-59', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'b68aea327974de7158cc880d705681592f84a06a2eea7b046d36e944c8de67d7'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-60', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '72b50ca4db1549694ef2d9cf02b3a68b25980064967305ce03a243d4596fd1d5'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-61', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'd584e36fc87dc6970d41ebe9f75d9668f357e7c38db74e748522c5bc7f71e6a4'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-62', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '14889f00e45c2673c5f1d9928340c913fe1805d28424e38bd8266a06e8a00532'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-63', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '62f5397947feff08eff7822176571826f012ea4f05b0ee1be762e52e311f5d33'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-64', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '8d51211ffb47fb50c3f9094b6892c5b989b4fb9c1dd1c6881d94a86ed8b81382'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-65', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '8fbb0a145942861639941268575f8afb6108100cd760da61cbada7917ecad152'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-66', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '55cb679cb7e15678e09a86aeb646304c78cd8a8f25b54b6aff1326f3ff256966'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-67', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '2a8253afd2fc6ca11a7ff4db10cd8b84541d8dfd043d9fa4f26dbd8af1084555'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-68', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '786a878884ff3288f47d1b23c385f4d8e1a4d63f3af626bfa85b649c887c5d31'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-69', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'ae360a21cdfdb3bffb266defc439ce421d88747ce1f74c8578861c8a42c54041'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-70', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'dd0df76c08099c81a51d9ad3d8163456848adcbf5d1da18e93fc5785f1e7d693'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-71', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'cbb0277aa36b44619ff8bf1e002601bb88b13093bed3bd97dea8cc6352d9de1c'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-72', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'd7b4714a1dad74580a5ebb2fbe8c95eb78dcb39179109f968a1e0767cbf2af84'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-73', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '220c5e08fcbae0710a459aad4b509e40e56c60c5c26a327adf2e3f3776abb401'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-74', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '4ef18a926ef8b322c9d392afceb1a931bf6f4de735534e9df7e6febb3ccc6281'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-75', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '15d66b825c5f196a4e2dca90fd9f05210bbfb54f0e393d00b01d06a81d043cff'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-76', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '0bf0e3556d51ef1a324d1c4a8fa95786982cc3f12ff4a6edd586a69f14712f21'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-77', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '626718f2cc0c272caccb8254b1fb23674776f5704ea716d779dfe3c69f2a1c5d'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-78', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '95ebb2f6087b6325de442576dac0b35383a12730176b98643caa5ac46ca1cb68'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-79', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '90748ba00a4c26dcdb580945ee193d97f0608c6c1acd3c88a4999338aa00cec6'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-80', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'a0a51a6838ed5a8d1534f8a433fbf43d16f359c737f7cc872902651d835693f9'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-81', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '7cc976a5c952c658d537d1fd35343314297d9624bd18c172cbef8055d5f0f018'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-82', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '83ba49db3b1b3ecf2781ccccebab37532a2c3579b94646cfbc5ef60195bf1d84'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-83', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '509b032f0a2e25fb4820251b3e9075bae002745e42ee0f489f179a69f037a550'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-84', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'e8002a68db69c68980bc16061ab0352d1586da4ea934cbbaeeec679ae4717ff7'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-85', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '8e297d720e0643532cc0f69e29ad309c5b83812c1009a3c71d3c5e9d7c321012'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-86', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'ab4faf2e164070e3cc6f07a13acf490285978b1a16cd05ab5b5b89096f6125ff'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-87', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '2f45f2a1096159f259e662c84d99500ba0ca1dbe680a5e60b7ef1c27808fb76e'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-88', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'dc7ac4394b6e55250adb06d556acb3c1b04e0ef0ab9c0222feff4d1a42ae8c4e'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-89', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '8693a0b3a124cfc582d522c0208c0a12885440ecf5d13014e20309ec0687f2de'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-90', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'b8d25002cfa6d89df5ac324d102f9139e562a8ece8ef6d30162346ac19a5d874'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-91', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '7a0d5eb864a6d92a0b3bf9520405e27fcaf5f404787370b3dac026fc52a0bf0b'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-92', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'df2e42f223258e0b04645bff381cb2fac3d8255f5e8a113e95df53783683457c'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-93', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '2f150cf57c8e6a9126999bd48cda7f5d606861b9c4668372dfc8934a09e3590d'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-94', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'fadb3e77300347be95744e9ae7c7a65029fa67b8a6107f2df2fce9781043933c'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-95', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '4bccbaa30cbe98595880558afc8270ec6dfa2eb049f92628b3c0ae3639e459e4'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-96', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '4fa729195ce2dfd7f74115240c671833eff6beed563459ed0fd5cc2163c1820b'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-97', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '601cb4d2ed6dd8b348d27927a7ce0a796c4bfe019395aaea03101ff83b65ce8b'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-98', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '8cfaf1885007dea5f0686ba6d1b88bdf82d4220a55837ac9b7c8a857caa70d8c'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-99', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'e6541227d0fc35ca32892c1f240d0897e5be79252b222af0614370003e4a1029'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-100', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '580f5b39e8c931ee5c8cc04ffeea2b67a8cb96dcc103a69e6e14cd61619e7dab'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-101', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '8827463fdb21853b7e83f9f098c5fddf042158be05a2a27f59ca73ffb47b0086'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-102', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '9f0dbdeca5b353fae481814351a29d770b30f22ab6258715b4760091cc184653'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-103', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'e041692c4c9870a9e9bfeac14295bc80eaeada25bf5b99560f72f5c0112b96d8'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-104', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '7372b6acc56138557c1907ff3d022c29fb2d057c5555489fe89e4ece06ff95f4'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-105', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'd53ab5bffcb50806f14dc91705b75e1104e089bf84198ca551b913f43e2c3dfc'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-106', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'a0a5240a623adcbbb685380eb323783e070470076582719586dc3b056aa234e9'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-107', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '7516da53821274f49682454b7507c91531b8338e27fbb1ea9731988dac39fedf'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-108', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'c3713ade5a2f2570eaddacf0625977bdf301e085ca5853abb74314fb424ddf36'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-109', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '6763d023bae35d4fcdf9d6e325e943cf56e59f4d4456def7744c6c9ccd23b235'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-110', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '6fb0dc876bb049ca47b36035dbfd7d02458449a2ea9e1c2ec9fe9efec2fbccae'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-111', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '495a27c741ad721602c6a454e552c0fd973654f65355ebc81dd8fe0df653bc39'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-112', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'f79fdb43256928e09fb50f3bdf20083d14657d5705e125bf9b4badd87136c6df'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-113', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'ed1fe8036d5280501ddeeeeac1ff4e92c94ce95fe160a85b2b4bebf92bb66d3e'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-114', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '3d502cfed5d9ccaa8bed8e361ab4a2d290ba3775134df5c0e133027251432616'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-115', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'b5e0efde4f86e477b98dcb63112675133af73ac0f5f29417c619c6da26c7dfad'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-116', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '073a11e3303e75442b9ebc7f71921d3cfb7a5e7912c1bcac60faa2edb59849e0'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-117', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '1006ce47516bc8901cf1c2522f65ee443a8b5b4f600e63c81f53b4093e50ed00'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-118', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'bc7b7352617b1db0fec4016513b0e01dd985ea0dce47ba5997a95a99185a7235'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-119', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'f947289c18554cdddee208075994cf5c537e430768e36ad6233a3d30db7c32c8'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-120', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '68ca41c6db017f9d8d16194c202ccb883065c39b0c545c67797be58c8fb6678d'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-121', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '764a3a24c30ff497f3806d64b358f2f105d935fc9d417cd03d6f90f80986a649'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-122', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'cdc4bc28f6c9b1e77b2fddc40c4522d8ca31e6437969c02632b29114caa31f67'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-123', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'd6f72b3d43ca67fdff932fae1caa7bdffe0b480c70070c0529da19f53b1515cf'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-124', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '0c3b4e37e77140c3bbc615585a73db19865f27f3b7785bdf0e70f04439e62d89'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-125', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'f4dd82e380b4566079062a86c5cd502e6cfa28d9c53b3e871077b0a9099a4447'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-126', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '6ff46e35597b6034bcc9d8c07e246d7ddc988fc7d5061d89e0fda82556abdf92'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-127', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '23966df95e90f5d0c58046886d13ed793b03170ddb32235a43ee9ca07cc1df60'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-128', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'b0f98763648c48c6182094dd091aaaf6b09344a183e6dae5b27bd6fd717c4a66'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-129', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '7a3ca15eef9fa5fcdb9d19849cc13c11a4ca6e08c49b5171c8b0875698533bd5'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-130', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '25299cf794e02edf4f9f69716bdfbef7fc35c7af7eba919203e8966cb368ace1'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-131', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '9fac8bb19d89ccb15b8ca02b07633d3de55af8e83ceaebbd2fcb459dd9bf9a68'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-132', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '937ee5e767fcb60d0be495199ac626b0e1cb354ff7df4928d4c4a4989b76bcc2'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-133', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '43842503293b321be03b6b1306ee88f9164fc9ae2f03725bc72162d73c04edfd'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-134', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '7ee0d23d1fe610ca30964e6eed25753abff101350ce9a0c0a8ae02e27fde73bd'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-135', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'd3da2a7a91c5814a868e9f0f564b46825b592c0e530ae5b77c6009b6f963d3f1'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-136', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '9152525c07b1a53a9f9f0caa9dd41277fc5eed05f9b7f5b77c26da92cc2d93ba'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-137', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'b2d0116877541f5ca9eba1a5234360082fffd3b0169ceffda1051f6934f92c28'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-138', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '857061e88d400db25fcfdb73012908c87986aadf594b71c152e839ef543b4859'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-139', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'e9ac289a330d69b38bb75dc7ca95a16a2a730230cad12c794f9844f627c5d445'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-140', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'bd629dfce048462ad49663c4da1531a206727b0399f0e666106bcbcfbde908df'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-141', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '314793a5a84ba7596817dc44817dcedf5916fcd031bdd2a893e4b009bd40aa7d'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-142', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'd089e49eb1b932ac914da030292ca4c7e4a343b5002c2ae166d1e2f4b9814dbb'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-143', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '95cf134afd458f8c4ba3b9e371051fbe4b91247500a4702bc7fca4a40df35451'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-144', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '460a15e68a8047c65b6865288add684b8aecfab376b8127353ca0ffbf8508442'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-145', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'c87bfae28fe261af014c6c54707bfc10ef51d01a684dfb4fe664c6969b289111'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-146', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '575da99dc99f0b92b9316a9f08457698a0516cc4b68d23eaea64e22a823fcff6'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-147', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'c287620936600b8bb4ead17c0a6037e67c0b1d2654b71fbef160b51747626d14'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-148', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'a01cdfcd54569bac944994c5b4a5093fc5e0d3c1153e0f367f11b06752a1a09d'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-149', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'aca81fd9d61bf2e2f0f8ea6a932ab7e4506f554547e85ae58ed221f2956bcb80'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-150', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '0c8a68bc6362c399e6c0bd94ab21340568c379ca0f15d6c1bee8feed577be7fb'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-151', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '0fcca1595520773fc0b2350835a144a8f9d3269dd2caf5ca9f9b0a66d10afe72'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-152', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '91b481f2c113a7850a2313e6e1349bfe866e28612fb59a628f2e795286ff649b'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-153', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'dc5ad71a85131bf5b2f1bc4dc7802ec76b82af789bb8876a184f90da1babbded'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-154', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '5a974eb0c5ea991a3cdd49ce45ea7331316745c921418c72ae1cb1b37afa328d'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-155', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'e464f4d9617c0dc3f0e9403c8cc7c25695817dc38a0f144e698786c4ace25c78'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-156', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '5afba73585a45c3e9eef9ac0ded09e4ea7c56d0b0c33202a60828dfeaec321c3'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-157', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '0a090ae40147ceb91ecb5c62cb88ab2220239f5e6807b15a5551ede020910659'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-158', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '1e46fe4b8fc428623b23e7bc21a827d9b5a07967df94984c5fae0cafade3cbd6'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-159', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '1cba3ebf033f7f02a6b181895a0389b44ad0a56391d192aa96b95c5f1dda4dd1'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-160', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '837a041f19a3bb1f45738d54d8ffde8e8fcb4fd04932d83d47592fdda546694a'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-161', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '6266cff14115f9fb510ce6cadf00227bb02e422030ce35b55daea49106600971'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-162', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '3ddbf04b2354291f23571a2c36137f7233923e64433bdd9ec94dd4a375d53e2c'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-163', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '99288d35c5da2f1a7f093dda404f93ed1f8e2e479daa9ff009414a4cb722d59e'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-164', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '29118dfc1ee4ede620f37f9e0b30e55f30d2cd3d9e9e52251cb1eee5e4300890'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-165', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'e0c8553e398aeb5c6380261446314de4bb57374d0f7b6fd876aa256d62ea5712'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-166', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'bd073dd2abf9538b0f729403b83fb67e7775411bfdb8929a8942765fea2b94f7'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-167', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'b0d33f850c7fa2d5030bb26633f5ba3be6aaeddb200d45301739c4200c193a3f'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-168', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '64e86d83eb3fbb51a8cfa5dde749eb6abefc8089644224cc0d189c18c15597ae'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-169', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '5558d5f71e908fcf110a24cf45d549957ce4f688aa767a3f78e8c298a991c85a'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-170', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '1d9fbe2a2d1fde1d0502ce7ec1a41db4ea4e63154e7f84764f87890751e93a75'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-171', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '817981733f9d0bacbf8050c32f008d9daa7d0500f19debb73ccf31685156d2f4'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-172', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'b70eee2c77249ea0cc2cec9a482f1deaae41479d951c60c2a7109e921e595470'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-173', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '5ebc17c1b67bce2cf0460983880014b07e6987c1abbf3bc6e65bc4f22a06cf3a'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-174', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '7abb1a9898940948348cecd65d6a89556f093f238873d20b7008fd3f220c23d9'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-175', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '5036191dec7c83b344604c3ae0029adeb97e942b907abc1fa0d400e6a0faec26'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-176', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '8a92b29ccbdfe7435cf730ea6e46d18281888d32d7b2cd9ab5cb288c3e80f0d6'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-177', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '0b57fdfc1bc59dd8f7e873ad5b6c657b506a1a41d84fb922172bb13c35f603da'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-178', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '2d592cee78ae48e19a4e6ac9b0c57ef82a7e66042c3f90c3d8e9cd071b0a2cc0'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-179', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'd98b97681db23929cc78f492ec6925165afd33930ab957ed8a0027852dfd3f35'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-180', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'e12eb20c57ca757099418b8932ac38666065a1a3d75634d4a9f818b66ea36fc7'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-181', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'bc16262eb2de137afc9dd99ff67ec9d3efd01fa1e99f032261ede93e095f354c'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-182', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '28e7880680acf5a80596428cf85812ce18577bc9a0cbf09a1343c2a06f180cab'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-183', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '2e3461794a9d3d681d99f27f0c9c5306415bbb0635ed500b8d43ddc3572e8c60'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-184', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'e806ac40422f808ea2dc437f5acc1cee80741a2267003a312de92b9e31af29cc'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-185', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'd060d9ce8167daef35961ad623fc105f825958afd07913e715a4cd8c21a715af'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-186', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'b85202beb02bc48eb6e73d4f92cf4ef5dd521ada5f7f0a8910ea34da4c976dd8'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-187', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '6a1c5828d04b17c4a10e6d611824c2c9922e8d59f01a07978cbbfc412eace7f9'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-188', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '78cd8f68251f028417e2f0e006e0f8988dc121306d7c2affa323c9a4dc8e866d'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-189', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'a443f7c46497bd358e69296e2e7986e5e3500885a980a632379c694b98012176'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-190', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'bafc361c00532a5d5a0b99df58ff99dbf9dfe52446e19037e0e0c8b311938141'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-191', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'ea4476edf25e4f5e1cbbceebb681be9674cbb7d7e2fdcd5ae826a709972a0697'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-192', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'c10afc6e5ecbb85742b1edec54f9d1d3344815672c5b3a804d8dd6e576013a98'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-193', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '0ebb9333038c7a76d026ab98c23f69b857d5c981bdb77d6913307e9eb5ed534c'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-194', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '067a0788131b984151c0291dfb4075d2fd289c58bf91cd5a230987cbe54148ef'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-195', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '953db7558577f8f7b4603625d05e9a10e5b8d9226d344ef9055341c6b85f5261'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-196', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '0c79a32391fc6bcf608faecb23f183b69678c1e5af35905cbea039bca4e75e40'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-197', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '5bd5473c2a26b3f8be874502d0ea310bb0c1a9eaf6dfb09a59317e3aba42a3ad'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-198', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '0acbe44262ad5a4f50c90e9b9a1caf80bdc0eeb94bac840e88d064521ad663f7'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-199', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '246507871ecc45519b3da4b5dcb1d80799295b0f3fa514bab2b811eaddbef27d'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-200', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '4c5fb8924ef8f3de239eb254aa96456efc401d192618b32cee2f9a28b0deb212'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-201', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '91068d20368578a2a3866b506f16abdb84cc04392bfaa7b206b5146e8b198cdc'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-202', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '501403eee26a64e38411c3300bf9ae516d9342d4faa77c990661d733650712d9'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-203', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '1ab2048a24eed19c98b27834bd7491640928f982ac39d7852c11bd1364936975'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-204', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '512e1bbd33b13613db1f9ace5ec9988a20fafdcf1fd8f2e2d9e3ff694ee6f590'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-205', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'fca8b654f776c2f63ec7437e2316c379af87818ac4b2a3bc48065d6c808d6440'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-206', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'f96983076f49a1364b2fb217a69d41bb55c1dd765fa2d7718c2a781b09e158df'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-207', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'cb6722b00b6b6bd074fedf3f325515bd2a4d9d91a0007e78a98e543b7928bc1b'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-208', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '9c4d0827c885f871062ca88e5c390b54c6322201611c5fe758209ba86bd2eb0f'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-209', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '230e0fbf50d93463079a28748dda44fa5215a7867f6a1f71b1789289198d1e3e'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-210', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'e651a4e769716f2f8022e3273b3098691a9d7f17584183eef511099a2007bbe7'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-211', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'c7ec2488424c36e56883b204586e5c5bb5528c7b4bd77c879662c983af6eebf2'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-212', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'aa47d02fe72522b9b0dcf73c2422f4e57bb1b157aafa1203d0ea394f323993c2'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-213', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'd9d932a6db4348044b00f25d8abe6c1f4f08b13f4aa5010fe157547d54984ac1'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-214', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'b5f34cf9c85765954782e71d73d8048e9913f80df6e2feb224d4807d8928be0e'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-215', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'e66fddda403430df02e718ff85094f12297983014533b6010852b0e23d8d0ff3'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-216', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'bf1c958ec6ca970b0b530599707897b30907844db1807c9a8680cdc75ff3bb0b'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-217', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'fa4150415abc7a03d436d272953090afe3bad2bcb5cce00c1953e2b69b3326a5'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-218', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '4fa414b95de81be77f2dec8c6335ad22d5bd91465481714b030ffa20f43b1fdf'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-219', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'bda65e44bb49d02c0ca3fc5f0a3a17b7baedcb5afffc8abed047c1cfe3bbadb1'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-220', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '36e769e514e0792a002248f54ec66ad970feb37655a66b0ac42ac20e26b04922'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-221', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '348faa7575a19b8681a46fa04ad8d1a6ca0412ea3a433aa5f3bd786645f8df2d'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-222', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'f1a1aff38d9fac8663cbd25fe7a3ecc35214f9b6609deb0f5a18a2a8211bdb4f'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-223', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'dcc8546821d3a7ed2274fc0a04ae483ec98d547c2cbba8f9a3fa44b9f19ab05f'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-224', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'c13a8e29bd6b6a447e6221bcebfcab544e6d29d4f7ec04844bb1ef58afc305e1'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-225', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '36b03803069b10abbdd3c4e2304481b0ab4c99a2e7bf1946cdff25831a821b00'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-226', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'f48fea87396ee255a6a4cc66a4e0f3ca65ce5799d206bcfa94438d11c91ef4b0'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-227', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '2457da506ad1170931442465d4107dd2bed6eb4043233ee4ba47204a4745795a'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-228', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '59c2c213d39d227963ef8b5c649bed1e9b884276ea51323f99b6c57b5f324256'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-229', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '7f93ef380dcd4067245ec52227b6a5140c93ee98e48b9ccef430f1bde33b5d93'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-230', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '97e92174ea57013486cf0c6049654e256622903acee86a1b58f20e817ac148a2'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-231', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '46aa73895671a4054c6a83966dcf34518d8f582d3e9dff6830cf733ff3527ecb'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-232', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '7ac1d2ee7fceae5ee317817e9abcefd34f06035b9a745e583dd67b52a1f64412'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-233', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '0d2ed249c062c90c3c1ffca36ea074a248fd1247044c64ae6cb101463c6ef8a7'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-234', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '2fbb07c68b205947bff0180e26ebf6b1903374a956ddc8972de177544408c27a'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-235', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '61f2e04432c5bcadbf5383ff97c21dc388a4b44533091e3dc65dcbd3552debd8'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-236', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '3960541200ad599ab98667a435cf21ec0c1512fb866fc1ea1e5185f7d93931f4'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-237', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '4c72dc06e9d7d42d932c858934d2e7f35000d854d1311dd845a6510b05a48b0c'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-238', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '9be54626460b5b67e65934cdedb4b5e77d5ff5d9b0ecc28e72a5c0695493ab1f'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-239', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'e375857f6a9540ab529d222ce82c21b27b3667d0cb399ba690a00757dd5faab8'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-240', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '15223a211264b47c3193a3fe30248fc14173eef0b92023c7ad3d01c5a495ac9e'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-241', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '27c086e550c839aada08ce85914f153976a655e4ead268678c8e2816222924a2'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-242', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '1f99b94f5c7c0cec9bbfd44f233552ef55a7ce93ae18aa8e9896df5d6c230c75'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-243', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '48e4cdf546190ce33dfe1b25b9b6e3912becb055db5cede9f0ec6e7806b18f78'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-244', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'd59af93dc7ed595f47dec07b45fe6438b844a52944e5506c3f217740b05313e6'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-245', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '8caa3e6e2d5c3bb1e4f86c448fa08c234b0555540d1ea025bc590aaee09ffc5d'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-246', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '4340b4b3021806b3c8c2e8be3123a0fc1afe74cbdaf0cb20694ca7313a69bd18'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-247', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'a44e144573f4032ac0d51e7e2b96d6b1d54d14f37d74dab74a00b7a9925586fd'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-248', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'f42dbcf2779df4f5e78868518246a525f00b0215007ab5fdeb4fc08c14cfb476'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-249', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '3e328eea5307599fb5f756397a297561df0d82c90ceb9c00d29cd78466a9615f'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-250', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '6c8b1b972325d6528ccf83e59eb6954b50c86d89b17128731b6cd82370f7aee1'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-251', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '4c768e4f76906e927284904ce0d2b3acbeacf4e85c6f91dfe94be617bfb4df2b'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-252', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '63a13f4865ece701c6026cc450d8b177a4f34be0d7ac8411370fe1b152904e1c'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-253', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'c0385d7d87cbd5cf56eec071640913e82bbee787167533da861297388c0cae35'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-254', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '5aa4cc5f7b65eeaf2037db7ef8743668968b7cb90fa415589bbae537f595ac6a'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-255', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'd56686f838941308ff87bc1f8c2de61fa68858c50179ab565824a491834cba37'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-256', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '30dcb3c067ebc78468885e0125a710b8ebb5379b2c6a7bc7569a1d24f6ca9ba9'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-257', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'ce60e55ddabae7ebcb51049cfe457beeafe409429c5adc3b1bb509a3255992e3'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-258', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '5c7d1ad92a80bf5d1adb01cf684acfa04abf4705accc67431f39d988da505bc5'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-259', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '62c36bbaceb61a0e5cc182b4b29a8659a140319749606084ba1060da2ff7398a'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-260', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '4b3a8b51ac0af0f487f242bd710109bebb009fdeae5072742637e76337b82fdd'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-261', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '33ce4c0798034fbebb9e99217890c12c660f43a34560111bc87e80b27d4dbb0d'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-262', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'c47a05264376781246b653bb8735e75a6fd546f3af766319a7fb18ae2104e66a'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-263', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '61be565c26dde3adf8bcd863a49bd33b16af7c09f8c5b00be3fb60972ba4f0b3'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-264', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'f77f76bb4dbbef0c313e5ea8f71a0ce3df75b52e0fe402f3b1c9095c361d2fca'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-265', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '9a6bace229b16965561dcb32f5ec1e779af0855af94d0f6f2d963ba3f965b47e'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-266', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '26e70f6fd0e0de89ac9799aa72d4a6e2995f3bc98531a2026b09e0455cd4f78b'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-267', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '0c4dc51a9e23593ceb39c68a458f132ac8624260d2d414d9d5981cfd8c24a89c'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-268', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '15cc78a980c2c3fe5644a5c81260c52acbad536bf448245b6b0511c311f4b6b2'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-269', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'd8d11275b7f30a6b7d697f2416623d3dc5576e0bdcb7b224e7a2f68fcc09d7ee'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-270', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'd5199887f899bc082f7b74cbb2945e9e9820cbe7cb81d4a145bb0f638676f0d1'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-271', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '0a4ba7327cad0df51ce6bee18da85d3023b6207f121a689755804f7407a02bb0'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-272', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'b924217271de4da32227498fab100f53f66c43296e0695a8d6c69fe3d489d5be'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-273', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '45654cba5985fb1caee9bf1867ccad037c3ce380d6fd9efbeb59dc955f488538'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-274', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'bb526440e3eb83cadba08d114d85a6eb6844dca256bc7c2072697315bb581212'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-275', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'cf049d5f4da10cb9299229fa45ad8f2adf0eaa8afc8f3bd5977dd79f7709c706'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-276', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '86496bd54b567be04ca4365d001bde5d94f9526ea2d3f8416e7e1ed5dad489a2'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-277', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '55a9a331194eb5b3ea96077eaaac8ea040877b9bdb0a2cc004ce9d804f1e14ba'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-278', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'd5f6615a540dcbde51722c81ab0ddfb092b35c12662efd67b9908789c3eab726'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-279', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '4c22087cd4d49f5e1b4d8687a6cd679a944a8134cf125b004e791644d7584275'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-280', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '04f0947739c53b0e9b494d1dfccd26f67e36f44f46f6dde058050005ea15e3bd'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-281', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'bb5c439cd6a6e603b1a654251bad5bf020395f4a7174fe6f4b50af7d9866395c'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-282', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '6dc86aff52d535063ce41e89863531a34e68073003c1615991c5d8ae202403fe'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-283', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '76e970d08b6522590689121a79e491484b1b63b56ef293c02873579660b627e0'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-284', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '846b9049f06d3387ec6c1f2b8c2282ffd14e0ebc0b0af2030d283fdabdd7bba4'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-285', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'b1c442f8af55558f00b031b2565458548cf0f555f3933a6c06bfc8c530507614'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-286', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '8f88744adc68d499a70566fecd9220c1fb448990d729044183e27c8740353c4c'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-287', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '259d52cedddafd00afaeb7431d6084ccb085bc8a3669c685eb46382672d33998'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-288', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '6baebcf24c4135888668d185bfacc2bcad7e4fe0a2f7a6c299b9bc0d96ba96c5'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-289', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '91e3e2ca6e4153de7e9871fe54fc2445d3d3a69284948ac90a21a48804d25d6e'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-290', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '9ea2ac181d3096dbd66d95c410f08fe01fd90ed9896526615fe049a8f429310b'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-291', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'e900f5469d694f86c0b633ba20e4996ec93aee8c9a4026007c9bbecdd34c60f3'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-292', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '5e313dd002a435bc4efce5dfc488d2d9df39bdebf8bb0fa362558486debd88cf'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-293', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '0b721f7875a7e1e4aaf98e5e5ca7b8ed4db7c9728cda3d09d5472143eaf68077'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-294', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '4f4b9cd49e39e0d632c581ec824fb1e15275a389651be594ef3a66b05c48749c'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-295', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'c357352afa35b09aa45a122549d8d7c72b8f1bb544fb4b0081f4ffe6f9da878e'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-296', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '3a7ca085f01af6458bebc9355c9fc111cce26c66f72337cf66cf383aa090976a'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-297', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '3c2d64bb9503b9ba81ddaacfd6828475fa70b9d275c3241881601a1345302db2'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-298', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '616afaee4db12af7790d11e05c60f1b6aebad505dd3c96153642bd0f0b56c843'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-299', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '8fabdb11283c5be415a38b778b1d5cefd68467dec2078b8f4034b004300e8f72'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-300', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'e259b66819d4d914df6d1a56c5cd70ab8ca9bd2bb743cf0a1dbc412892becd33'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-301', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '1e98a7613ca366e666cc0dd015fda9ae88a0918adc7fcbc66f2f13e6852b136d'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-302', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'aaad8424a19acca3a7482e3bee491837319fbecc470d9dae7054144b8af4c223'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-303', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '2a908078c7af0798b2c81fdf20eaed36041255f7cee31e283aab7122bfc31b37'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-304', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '49841b4bd48ad387fb7835fa826a5077572f24df3d372297c3e155485dba36b6'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-305', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '445ac6faadca9531935e97e84971e16eb99e992c445815eda522c1b6a9fc470a'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-306', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '9fac03a6043cf4c58d66597b9af8c89412c0466d17487506c696467b8455c9ff'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-307', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '5c4ce91496e2c5191f445812786e3003f004cd7ca136f01dd621b6a5d13f56e7'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-308', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '203ee55a49d44f8fa592471be56bf1caf91510145c4912b915abe647296e9e38'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-309', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '60c183d40abb04c643e5e3f8009429e0427a266f1c4ca8359ea200515ea36290'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-310', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'fe022c2ef4cba3ee5110d0d6050c14b3ae485be335b7285b1c1a72c60f5c81ca'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-311', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '66bbe191118fb28fba916e9bf02d88cf49979865db43ba0e4b26a639c7e0bc83'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-312', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '16aa688116109f107c6917d51e21a8fa823322f0b9465426c0483633a88746de'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-313', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '03d135e071fc2564f62deee3e4730087eca6ad3b191f84e34dd95dea6ac61000'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-314', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'ddaff1ecd93a1f6dee07e63d6ce3943f58c56a0b6d47ac843419822719d6ba3a'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-315', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '443d24ae74df2ccc6bfcf89708199343c3c7bd2e0ff54440b69dd82d0770632e'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-316', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '7aa922b73a10cced95ab9e8ab1f907e7192c4ae389a50e585452cdaa8441c6af'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-317', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '06f7b771fbcf3d1011cde933f85567c5b45782ff9fd7352a0a6e8ebb2819e85e'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-318', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'f5151f4ddab19a3f3f051c60b243030c58afb6940c81a06e801e2fa93f0b5d21'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-319', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '37ee43ff6f9e2c484b6c9d6d065b38c4ea51547946b2d0791bedee12a8f06239'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-320', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '2b394caf6a00478441cbab994aa26ecbfeaef7b64b26c20aacb933d9a6664b60'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-321', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '5f349a4474d221a97432ac330321cbda51cf26cb694f517c4e7b4098dfa1f5ef'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-322', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '0597d956d130549ac521c3724562470548f922d548697e358a78769b7b41d193'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-323', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '062058d5f503eaa48e00760062f7bd122c16795ed272e89c6309081424d0719d'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-324', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'dca8d9100a88b7e9b668e8cb5faac45a88245c772ac034c185fe52754e790f66'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-325', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '79f2654b65edeacf2433815331366101194128d8b3f471336b558894fdd24a33'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-326', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'd04b4cfb4bfa31a2fd74dc3a1f55fe58fb5accb9b2e633ba812a327b5c47a07e'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-327', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '6865f5059e7a9853d312beaceec79176a21830ef6fa4f8e62586778bf2aa5ab5'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-328', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'a6c6d480680a75c720817d5579abf85ab21ab1f64d5227e6a807fc1cc2c54531'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-329', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'd8b7960ef95634e4f1cd164239de2793108986aa4d56afc6928192afd83f50a1'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-330', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '4f4e571575b8f459876f6ee435ddc6db7ccbbbe2f415dcb094dfd0187497b0d9'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-331', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'efb370e9d8df26fe83b7d0fcfaa82e1714617e62a5e501027f686f96dc7c46e3'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-332', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '7c1ddec120f673e79af25c49bba9462700967adafff95429b529dfd9ef2d2a08'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-333', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'ce1cdb4ec3310d1aacad14c2feee5d503b8d6ca40b5929f9736682d03df9afb7'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-334', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'e244f0f673e79f80c777a9fe433c6dcc611bd12abebb3ae85063fe4685a87fd2'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-335', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'c7346d35543d0b530cc01dfbecd12038b20b571380f73186a9680ac6ffeaf275'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-336', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'd57ae6aa5122c1fee0574456dac7b71d872d58e7284d65712af836901aa19feb'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-337', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '0a64a2d8f423f44bf5479974611aeb29eb0aa530d924706b9b9df2178c84c027'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-338', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '87a337105cfeb629f630877c620b7e0fd6e308ebb481d410f5319868dabb2754'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-339', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '7fbd7391cdbd410b57110bbe6dbf8c55ec86a71cca15c4a5f523c2e583a7b106'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-340', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'a29935dfdf2c1ac00751f50a2022f018effc0012c791430a0b9ac3e2e0ec276d'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-341', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'becfb9f81f480b002c3ba760addd392a80c8cc7cc44359d3dfa99ad1d74165c2'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-342', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '7d1cf093c6c41cd23296196a8a20988606a9ec0801e218591c892d05f2a024b4'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-343', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'cd4c7443a9e37a129cae6a349e533bf3bce62799475c6e29a76933578ac89410'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-344', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'd438b53f3805c07733e10cd52aa6e3fed6a9c4b6f05e1ce296618a9cecb8c394'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-345', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'bdf45f602b12745575078f8b94235c70a9e87003c3f9225d18e6fb7fed9bfbee'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-346', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '9132a8106835c8ea808442aad960e3a9d2027f880c12550753188e0a5a850c5f'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-347', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '5783aeeed55fd442d69e93e419207c9f9417d6e97c64b5a50793f67a6529bb40'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-348', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '49ff9caf76f14ad768fde623523e0f55d6535debd2f83fb1f07d76b695a7077b'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-349', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '6209debc5d7cb04e6cda9f1bd9cfc7853141f371eff68cd1900806a7183a0291'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-350', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '8126aa76fa4628d6104305a4d1a4c411a0e7e1f133f9cbba31fcf13b410c7d41'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-351', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '45e2f7d3b35218c0f965e9d9dfbda9d7379c81d9ce5398683d8ec71aa64a7b87'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-352', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'f0b77fc677d665da409e9123378e12d39d9a89cfa23aa723139ea15ae7b3fb55'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-353', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '4f70419eefcd18e0a4dfc4a71f2aaf13d75a66fded814b6068cc99332c21522c'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-354', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '08aa9d6c5e0e804534ce0dd89a9dfcfe5b3778c5db124e92764224d4d7b3d27e'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-355', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '40ffc2cf23255e6fc55b240192665661b790da50d609d82bfaecddc6f68a1840'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-356', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '90269ef689bc328ba524433e9a0f25f812ba968cd76550a0c4dc4f7345983dff'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-357', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '51a38fe1e0b00b0901635bcb103809615eb9effe595e50a7e7200a24bc5948a7'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-358', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'a2a70244f4b0f440f7c5762de1d9b83526d8b8b6079417ee80addbc3a18f4c8e'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-359', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '64080e17d115a5ccdf532a16909436e7513d2733314b99f760b7a3ea6aa82fde'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-360', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '04c8e3c84e349fde7de391ecd32911577f8801db4a1a72ed36fe4170a4c5141e'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-361', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '3164c67e1790cb04ab7201235dc0fe4882f13b6783e1dfd7187ffa91c2e3412f'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-362', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'c7809a60036bc1fcd14ac6b15902f595734c6b132b8ac4a8ad58915b5b119cd5'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-363', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'ec6c6e9fe3ca56ec8262873307d6a274d8adeba65bef15ded0b99585c5f84d3e'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-364', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'ca22da35218a7ee1ff69a3261dd9271f0362363acae30276e5b1c017df941f75'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-365', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '3be6ba0b7757cd7571116fc1ae22a0fda3050df46179f6641b16dd87db8468de'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-366', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'b24586658947fda059ce2dfabf8a3969baa790e23d41f999427d26ff2e0b2c9b'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-367', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '43d1c44444274a046ffce16f233e41250a093fab6b82412bdd09d782669edb2b'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-368', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '9c188d10502839a3fe2378eb998c7fc0de30478e84e988040275c0b889bece07'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-369', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '770bab8d0110540da2835e4b28b3f654a2ec0e62ebeba18937892e0a5645e130'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-370', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'b91fd49109ba0852ea7b2177dc7109e24024e3fd3d6a5ed742f1e4440a75ec59'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-371', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'a6a84be8ca11a362c1b6e50b8b79d6f1de87919bf04db889048c1395fd61c091'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-372', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'a16586ea4abaace6d1dd303c285291dd8a2cf1a986637ba950e6ee594ef85d18'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-373', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '3b62b1a5e1c259afe129f2fc58ad8a3b2c36b2e16da352bff6dd0b15cf4e0e93'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-374', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '4ec305c30a4588638f5e4befff8a573e64a7c3b27debe777b6866c0fdfdc2787'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-375', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '2862caba565ea1e306897e30bdda904b4092b8d25f639811407ab0c65ed99efa'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-376', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'a47ad30be23b07ea5d9b6efb344e4917ac090d024949e078b6040df7aae120e8'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-377', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '25f879acd75c3d4cf20881b605987b89050ab231a6997c5e8015a4ca51c0982e'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-378', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '0cbbed975a926f06316f0108cdce921a2a820860e808b3e115076d705cde04e2'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-379', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '9568ed3f5d7c6ed01b105994b387bf5994235e91c421c9716d4c1046f71c81f0'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-380', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'aef64be39e0bbdb44c0ec9ef8d6a3fa95097dd599d2f938e35035a4ce37b5954'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-381', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '0e02e84079122d64d421aea89ac5b373f7096dc0154f54c1df6a3b6ae3786abc'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-382', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '9395172972f02be435255ba86266fd3424f08bb2ffc09ab2d7ddd8ad49431f15'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-383', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'ab4109169038307675c570cfe95e5886dc5b6524fd983542b788b44284bd21a5'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-384', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'a2f7090c30050ca1762c11bc6eb7cd55cc783af99285f9f5dc4f32d31f396f85'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-385', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '6a97c82229339d102e7bf34806bb256d63c0828df173096470d27b5835dba9f9'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-386', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '3c5cdb2e7e30b8177f81c8a0698812390cbd245a4e91c1bfa174b4b3ff29277b'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-387', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '06052b0cb90d5582bd2bbec941126fcebaf678928c9d84e697c9796eb2df0fef'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-388', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '5eca3c32686782e3c0d125850ebc43d12e216142333cff1b1bc9489fcc03b6b5'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-389', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '48c51220c6ae63f0feadfc0c3076ebea6daa4ca23a0dbd8e9a5d0345c79774ae'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-390', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '93caf8b6923873aba98f745a4d8d1a810e80ee6306144740bad0cad0fa61fdda'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-391', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '532b21c9c1f04aebcaaecbb6aadae682da5e390810c0663a432d1b231129c252'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-392', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '4c8773331b042f9c87f3cef082f491d9f41cfbb03f03c95c3073f9ad8329e2c9'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-393', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '2174dae85666ae5a2337fe70b754f0894c0e9b4363bf8af3e3f07437f311895a'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-394', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '2420148301fcc41de273b9826963476064f871c02a53a0d5df100442705bc68d'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-395', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '928c4df2ec0e85ce145cd432fd5574814dc538af3375f0d659d62c7aac914e6e'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-396', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '86b3d01012f069f43da72a35cad9cb6e19e4e7148f43bf87dedf34f70f1f9a37'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-397', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '165bc1e8fee434a6e2911282be73027dc59db0f677b180fe7e731389afe7e8c4'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-398', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '161cd598ccf6e54b8f91e1433b87cfd540e1bc20ca7c7e1159d3203b68f0517e'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-399', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '4011fe6b3d0fbce09a822f1edd4434f5eccf985e0a19111ef16cd39db6f0652c'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-400', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '4ca960fe5cca948c3a4eb4e2a42470a22e27af42437063b45483d7c8aed8dd42'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-401', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '0fc233ad889981f1e0547f958a78e96614e5a24aff055c9d8b7a12024166bcf7'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-402', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'e53403cf7345ac2f42c423e19b4afc2f823c744b45d71365af2ba778ed9c6484'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-403', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '4a5bab53df5ed50c0b72cb9a54b10859ad26acedbb51c5190ece27b660897b27'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-404', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '4086cfcb561f14d0d8fae32f6069fa111449c59a5ba51cb6240d70a5923fe69b'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-405', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'fd28c754f06112463d5d229d817028047e593d3dea01ace6e12987e68a2c8425'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-406', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '7ffd64b66566b6757e45b95fac0fbac1202400b3a3c616d2db0ef33a8df73b68'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-407', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '98bc08045d4905c692ed7cc4bd52d24661d95ee7792991c0eeb811dd32e60da9'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-408', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '72e7180f4f7a9bdb484fad1ad703644d661eedc0819df6280fd58e702e2636a7'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-409', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '3e439d5bcf982a642b1104842bd41e0c83903277947ea081d7572360b4d013c4'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-410', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '478a5bb43e1524a13d47e7be81864491ea9c457447fea1cecd373b571fdd44d3'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-411', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '6e78af8e85a1467d0219583cb21680410e60112c6b14bb856f19b04a6341cbdf'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-412', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '4caa754420d52810b0b9fa7ed64464b6af20c771ff381f07b0a2f9393bbbd45f'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-413', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'eedfa8cbae2b80c54568b4e0c216872d8710d4712d0195cce6cc5c529a2cb963'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-414', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '599e86c9a4427b32d5fd31c2b13a260dc221d6f23b8ab0b0ee9395733d33905b'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-415', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '83baef4a026f4f3aece54835763437d97416e8e2eb21e826fdd63adaac3d73a2'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-416', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'c7a27ffe6bf34966843d1942096435e701b4b5fb93c16f4fa346a5ac8d4b862a'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-417', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'f541250fa33513328a3f0e3abe12c718e29a91d4352c05fa9e05671a7c11e70a'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-418', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '8c934dd5055f094e8d0fb002a004f4eb72ddcf5f9c5aa151aa60d322c6d30901'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-419', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '80950b7c6fdd371816f49ba259a6d7cc361d68704809038f4796d70422fa26bd'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-420', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '8b02020bd131f7c1e96d0eaf63401edb06b54800ff66733981a3865f98e92102'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-421', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '50b7a96f01f366b0a8c5d82bac9e860c45f0aa8de8472f521525a4535f0c80a2'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-422', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '8a06bbb75f9e21b7e2c6df69968b712c0699870e582914cfe36c42bd63916299'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-423', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '7f254170ac6646e96033c34a32a62ffb0357e1e1310b90bbf3bbd4706a3f215f'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-424', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'b96ca4933db1904c91b1799c26fb52a70faacb182eac099a31068d03eaf38feb'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-425', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'f1fd2faec9a31eb9845914977986b2a7859879eb91fe5e7287d28b077a2fa98d'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-426', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '4a08ed85d17b9d2b09310f15aabe5f1bc1a4dd47799f0833bae48960a9d021c5'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-427', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '3db49a19dcc56bdad9d30107a0786c54384b7768b103619e0167b00f0f6edd44'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-428', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '3fa6f4cd1ea835983abdd25bdeb7758f5827ffcc1e33f6df6c9d264e4f18bac7'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-429', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '60ae6b169d89028a4a367ab7132033c29bd3bb8f6b74a440ba957fcf60cf01e8'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-430', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'cb094c4075ec6bbef83862be343b80839584766d0edd8b7e390fa91ab7a3e3ad'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-431', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'cdb4fa44c324de63b96b589e18eb602d84e8845f1cfe1aa8a53614b2f20758dd'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-432', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'b8f64f16d9dee84f1ed61830c6cf602c918dc2984da558fd6f9cdef6be812bb8'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-433', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '1c76bbad4a66bcb25369f5fff26b1919aac319a6be0e84386a6d8bdf885b5c88'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-434', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '4a81055dd656056ada4c071c4159ea27fd12854a95d61210d68b9a810a0ba3e3'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-435', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '4ee11e061101343c50b5a9d2138721c12c63788e09a4e9f54a547fa2e7db9076'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-436', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '59073b05fb3b2b59208ca6739c8422e60ec4b18b9b3bd8ba98caeb338015e7d9'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-437', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '7418d09bc47debb9650c57b164322d24f85d792006b9ec885367b4eb99483b47'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-438', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'b16ac7f397912d7e917f6c62787dcb692e8fe9eab670d5bfd42f564f7ce19334'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-439', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '8d0939e7784cf3b100f4763a6f1303347a0b07a163f3631275e6f3d504fd0cec'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-440', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'f07c3febb8cfa1c204ac3b793d57c30cb2dbaea20960888f2b2fbaf8cea8f20d'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-441', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'b9cea85dc92e701386d7ab55867b368f45d5ebd32ea90a164025d6a17315ce74'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-442', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'baabe29423a5ba159e5ef8503b3e5cf1117af53803f17d2cd1a5a0ee901ff9ca'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-443', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '04774c1d5996c5b23384dc05703665503c2a48ce47dae1d41b1cec73f5371c77'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-444', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'da7409a8752227bd768451cb5e44e350649bfa0bc7fdd10d1187ce3f2cb2b632'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-445', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '75bb6295f40fdd15ea7e308d17bca40008be60f65a9f0b8d53384a48d2b4ded7'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-446', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '0f69c6712a0f79d36c6cfa97e2b60c76439d587eea58dde1e99d8397fc469152'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-447', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '16ddc825de10036d9ec181c3286fa47a12a3fec9ff51b9cbb7f9490c3160445a'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-448', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '9c09055d269581cda46a3affddc01319df69ec184aaf343bd6fb00cb0054e606'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-449', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '952f1bec2ba3b46a3edf0d87f6dc3be036d1da168238a3b28439287ab0ecdc01'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-450', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '271ce85e0a28c1cafe2f748507cd9725f62ca71a6df860073d33071eb16860a6'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-451', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '309f557e517fa999f81ecf31ab8fba0faf0b41f925a8291e18b8627e28ff1dc2'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-452', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'b4e54638b8d291ceecacafa661fa524a0e8f0e7c6eb988bdbac093c94ed77a43'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-453', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'f3e1e346bb610aadb54b8d224772cbc90eef2f19a6d7e435ec2876e382a6a1d0'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-454', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '664883f7d86aebe82d1127c9af197637b146af9e385acde97844d2b2df540161'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-455', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'ab73b04a2713fd9069dbc4186ac51c3d099d113e3d1078b2f2846279f87e1d79'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-456', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '711687f1adbf7c6b6e5fac2be51b68164fb7f138fc65e72879b08a02c9844349'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-457', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '13df3161365278a9e7cb2f8d7cf1260a1ebf26a5db08cd9e9b5a187faf6ef8e3'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-458', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '228171729ab6bbd4efea98546e55e850b0bdd1d6d487666b600b99646fd4209e'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-459', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '05b4db80b679525cdfddcaacec64f62ac5bf7b3348101cd860ff3b5283db26f6'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-460', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '032cb08f862e652d1728c7a39e0da374428ae0ab9be2e7d6ebdf07b6625c5406'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-461', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '3e608c185c830114de868f493b73683d23c24df85433cceb59a900b7f26d28cd'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-462', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'aa25714258d4813a3e69e559e7f00a55ed71e8f6515ff31f7687f7433c6b55cd'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-463', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '2d779f719e2a9cd3e5b1bbec21951af9bc5df9833fed58203bd7a633f350f30e'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-464', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'ea5583d38c1414dffcbce4c480725032d71bddf5331b55954fead11f2389ea24'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-465', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '5bdb538e8d26f7b0b694e5871af2086aed8a576fe6a93402631f5dff02010306'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-466', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'd32d59417fa84d2f2acaf016959ceaf9d38b0d184123fbf63ea9a5df9a4ff609'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-467', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'f2244a646229ac4c01adc118819c8bc79c56e077996f09b7c733a022e535790b'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-468', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '66ce254c5dcfdc0d9bc65e16cff33bd6c42b6c97c6c3b442421097280df72c29'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-469', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'f51d7f2015fe6437887a0fac6403f60ae774060403735328993927e6f2bf4d22'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-470', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '476ff04c4268735cd47d844b6c920aa6b03a21c75c184a3d8ad180bb14656b84'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-471', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '565563ede3d352506a605cee6e21e99bcccb09379f82300529dc8d4075f8e629'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-472', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'ef580ebaa88f448674cd3d99928792987c87d25892cab63ca56a515e375f3417'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-473', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '27adba176cf472bb11a974fe90ceeae198acd14ab664ab6b45c436c25c800a7c'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-474', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '2369e7d94ff745f71a3e31d00ec581165bbaa58b00a427bb152d0bce6ea00cec'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-475', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '860a4b191865cb8709a6911fa48ed87426f4ac3f34364f17826dfe61475013ed'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-476', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '46026f4c987add596166dbd9c483fe13f5326877293cb7272f77a524de57b1f0'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-477', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'b648d0fefbb4ecd84f1d19416c2fe13ef1aa725ed38faba8556da9c72026337f'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-478', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '7a5d59e3b1ab3a4d7de8a324df6885b7ca454799f9d0a685d580917597ff691f'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-479', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'a25adba3f19411db71c7fbbf0e5112bb9d8a86ff340f75ec5c80afe0023ec83b'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-480', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '8d8dfe6b4622340035cd79706b00bb1c2f5c9929fda40b90f58d376eba0677f5'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-481', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'd5d9afab223a3da2931156a2c27255b766b9c23b2331fe3916b993fee4965463'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-482', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'ca9edff1ced24f88fa0664c101b74760fb897aef053ee5dd040c7f2a949b731d'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-483', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '16290c19ec89b36f71364d0d9b556f145c73030cba88864d545765902333c643'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-484', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'bd006563d7ca2a3387a51b30cd618a9877be5de95aa84f1ef53a4f68c895b83e'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-485', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '01f1be7272267ca83598bd07c4920262aa00d41b83b1ccd8d6caf3eb95c21fb0'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-486', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '2fd4d3ff89a15f94fcb9e48ce2d66c83cd563f0948481cf9db80159ff40e2290'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-487', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '3eb75936f7cc42232a7af7244bf10e58eb0aa83b9e872d5260dbe414409f2361'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-488', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '5f957c5072cb81ddaf2de3439005e0e1df655ac09a6604a1d04d71c039dc9bbb'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-489', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'd09f21795e322c82af386d8f60f6ebf7da034d40cf404e692c9eb668722bdf81'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-490', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'e69a1f9a25d152f748c0114dd3b0fdaea469a4206b89d56872d51dd75d0ff1d0'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-491', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'ce87b0a59fe2e8759824d5c05d8390d9cca29e5a28afd8c16710c2e40889ab2c'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-492', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '9b283579750e32d3a3cb8bee0331321c4746e220ac67367629c1edcc877137f3'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-493', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'e8c48c8958b7f52452eb33e71528fded7dec3612bf02c21e1fe70974436216a5'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-494', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'ca076dd3d53b4664f75159a98696186801949b786eea574c48c07e0288bf35d5'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-495', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '907e3b26e2d77beab63f8a3cfec6f5a37e48eb978141b605b0a395506e5bd4f9'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-496', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '3147529e15ebea17bee4105bee281fc328780d40da212b97c7f6b57e56082f5d'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-497', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '63a7298fbf62dc573b95a165033c350ce1fc5f6fd0d1407fb4c8957d46ccc6e0'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-498', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '6ff3e601c2fb5f9f51dbac906485dd91cc0e02caa4d267fdd35714ff90db50fa'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-499', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '1517d06f3a92477cd74cd60753046cdc3e578c5e6a885cd8f280071b217ceeae'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-500', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '9c9cb03add334c0d9a38a137b82808aa82ad432d45f80f7b254d0af8e1e05854'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-501', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '153272d3c3e3de321b1e950e78a047dd2f31b9022a79ff362fa3045b1332ee69'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-502', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'f7d0a16ab61207337bab90f239772f407056add460e5d242094501b2f95fedad'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-503', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'af36f652a23aa7ca3b060d2ce9853befc7300d0ca6a73a7d1ef5429083e54845'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-504', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'a17821ea7c0b78222723967c1820210feb30622e780907c2dce2e568996a1034'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-505', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '02eb0f01776549818f6eac04a95cf2fff55be97f8c8d006dc913fe0392b34d16'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-506', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '89a36906e5454b3b67abc4050d8d270a94766bb51d6b818153dbb4b4d3700cc6'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-507', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'b4fc90194afebde14eec60a24458431b8a40516b57801e9c8141442f5c71596b'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-508', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '12bff28e87861175ba418800e408bc55ca3893515e0c0798765b9aae1ca85176'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-509', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '15fa71e3af66bdf74b2cc05dd75b8bb27db1eba5baef6c6a2f74f0512f199d82'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-510', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '0025385aec436be6eebcd117664825e9ce707f67f49baf8f463c45854e1cb749'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-511', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'c29080433ccc4cd2144069d02c16e3dc0949189ec5c14ec276ca3934dff81954'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-512', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '61bdd25c7f435acbd090eed30708e724b5b5ec6dbc29ed72428b1b5ee75fb33b'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-513', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'd501c73f37699c01fe5aee16f3782c02748a9e063b797bd56264677ce322bab2'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-514', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'd3765179f0cd0287117ad1449c780e0e343e791c862f86c7f7012e3a7d0ab373'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-515', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '71abcdf5246f605bcdfc0f4ab52a80e04738f3ee72e5ac17cdca67463d0af8f7'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-516', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '4efa2c4a601b0ca70de7c59b7b860c8a474d17ebbed36b0f04897136f7edfc26'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-517', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'ebc4a00e0bd0674911e63f42256ec71ca76cdf7749f40153433e282b339f4611'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-518', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '00fda2f1584006468fdd03f5a89eded76f02736716bba31ce48b72a62c315ec5'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-519', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'a1be8664d1a5c7cfadd5cae5f74fcb293652a3db8a50d550478012ecb828eb4b'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-520', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '8761842c44f3551dc9d6213dda05756b98c4f79b4b7a15f64deef57aa638ae62'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-521', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '390411140584951ea69335a99dee775e33ee2291249705d6a13d4b49c5792483'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-522', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '3f6a213afa435e71f6b00f2c87eee5f3b833d881f524a0b08ab0af17aa427271'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-523', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'd3eea0a474e61f8d390811da11d763342582f0b9ec1fd027c9158c8068db5a28'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-524', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'abe5801f1ee6f2268abcaa511d924e3b01596b1638d9a47abfcceb1bb9ffb9e1'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-525', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '8c7452ce03ee88148338f95ef59780c3c02f5df86fca77d991a45d862a94521b'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-526', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '8f667907bc1788b49a78864e885a37777556298e9087c0fe976f424af0f9a126'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-527', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '1532bccea630e9e1e1b0ce83f93662d09b1e518134b54a64f97886ac1b37b21c'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-528', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '4729b92dfe677262eccbb2cb56ca98e442590a6645443da18119ef94e9ea1c20'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-529', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '57e2e4fe9ebe5451189992c3967920076cc0eefb49ed766fda68b0ee537d1ec9'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-530', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '5fe1ba0ef13d294b8bfb8c5468cbb2678d0750281eb59ccca3fb0544e7534008'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-531', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '0d8dc8e462652b25a6b0ddac4f115db757bdd1e39a394de953b220b8668eb485'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-532', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '75e5d625137ace431d560fc15fddb53344df4a404a1c9b4879f8a721f33bacfc'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-533', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '16d9e32dc0c57e39f4e6dcd8ea1a61c55624047428bcc6277901db92efd2f5c9'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-534', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'c0a37b6b26c9b6a641b548135c0b1ecc8aab47f61a4455ee236126a9af4b0460'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-535', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '69aeaf5c16bd526bfa69cc0ada9545a7871e03c16420efe343748847343f2608'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-536', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'fdc1cc81037243f4b5f4728dd79c4b29579e01b6fe5bc2da39d412aaddaff68f'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-537', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'c5d1c6bb14279c88a8b51549b0288ce8458e5790b52cab601657b66fc9b68fa9'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-538', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'ab416a108e21d04e9912b634e9ec60ad653eec7a9347d4927b621be932c931ff'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-539', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'b1fdec9d1aa858944f411179dab9dbea845c37f649d31d251240c184f82cfb49'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-540', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'dc7437850fa6a7f063c497d5f0abc7cc484c1e961777e12ed61d98cdc37c3a94'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-541', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '4583f36032374821086b1b4649aa5ac09b6061e4c4c530cd531c1b6a0584ebf2'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-542', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '8335518564a5cb9527df4eb604466fb8f1c49f4cfb2a10a603b995672a63888e'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-543', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'fc0307c89cce5069c7db60fa0563ee907a03e3c467d39050bcb7dc187a5cee7f'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-544', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'df38277f253a6ca282c6b892aac5392d6c93a8d6b22df41524bb0c82de71cb98'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-545', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '3c32b6af2873be7674653cb8775760281f7aabd5fe43bfc6a7bfaf38f4ba740a'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-546', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '05f75a8434ab0e594e77456a390bfbf936e4158591c18a143a4196a4d2a3737e'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-547', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'ddedaabf3bfe865b238961e0fc9d1faefc435187d7cd6aeec01efd15b95c3194'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-548', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '55a4e5178036bef99d58253de229d44d3872eed09e1cceefe02bd8bc6070b6b7'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-549', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'ccac1ad057eea128353250c52959eac73d3dfcd29c7f6a18e1806fec3fdcf70e'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-550', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '1de4e13ba3a8492a8e416f6c00850228632ee50f167b4f68c72c9a50e90b80d0'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-551', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'c2a24f0ebed1d435087bff68ebefa9ae41ecd0d6b1a34bcda7df3299f8506df2'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-552', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'fde4aa5ae50a6a72cbf99a88b75a13f3bddd5df8bff6ed0ce79a4ce2c1e1b35d'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-553', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'c62f83cc975af1d71f9cde17fca905ba5d4678ca296bfa4687af6c6cafc2707c'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-554', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '2524e512c27239707d1c2e87d25ae28c29a1c455b1645791e05e9c5927275d55'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-555', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '58ea601a8e8c94817a6d4fe330ef88f82d029f8b71d5592725ec2113532eccd2'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-556', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'daa08714a444685610311c47fe4ded3abf9543cb66e3dd4fdfd0cae84d756aae'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-557', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'bf7768213b9f0898323b835e31f51fc957e29502c6abf13d8e09416f0bc05a50'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-558', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', '01b3115324cce1a330934f07777f17f4c2f361523c1660ed38ead4148d37cf29'),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-559', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', 'd66a63f901a19cafc3b9d6b24299e3f869c1ed4338c56fb95ef5dda645a71fc5'),
    ('nfa-test_display_source_view_masks_credentials_partly_consumed_by_csi-0', 'tests.unit.core.test_primitives.test_display_source_view_masks_credentials_partly_consumed_by_csi', '23b2ffcee33b12579f9fc69720866dad8c282cc5fab55f48258c3e2c37774689'),
    ('nfa-test_display_source_view_masks_credentials_partly_consumed_by_csi-1', 'tests.unit.core.test_primitives.test_display_source_view_masks_credentials_partly_consumed_by_csi', '2fb22d9af19b4150717f70fce66f36b320f2c9620c7b646306cc546f5c146a0b'),
    ('nfa-test_display_source_view_masks_credentials_partly_consumed_by_csi-2', 'tests.unit.core.test_primitives.test_display_source_view_masks_credentials_partly_consumed_by_csi', '8ede7cfd11e7746b81ac4f8a72372abfef044070447bc6d425e407479ce4836f'),
    ('nfa-test_display_source_view_masks_credentials_partly_consumed_by_csi-3', 'tests.unit.core.test_primitives.test_display_source_view_masks_credentials_partly_consumed_by_csi', '37640dda739bcb62ab457d0f922440b006650b9fb72c364ac27496903b933961'),
    ('nfa-test_display_source_view_masks_credentials_partly_consumed_by_csi-4', 'tests.unit.core.test_primitives.test_display_source_view_masks_credentials_partly_consumed_by_csi', '6605b581fe07817a46fdb4b796550e56031443407d6def262b3e294956949e1d'),
    ('nfa-test_display_source_view_masks_credentials_partly_consumed_by_csi-5', 'tests.unit.core.test_primitives.test_display_source_view_masks_credentials_partly_consumed_by_csi', 'c59271b63472b862d526f44db5e1bd0c5c6393f38f486e13e9d2c1df40f6748c'),
    ('nfa-test_display_source_view_masks_credentials_partly_consumed_by_csi-6', 'tests.unit.core.test_primitives.test_display_source_view_masks_credentials_partly_consumed_by_csi', 'd9653f327f7ff2ca5ae5ded537aac0c85b0afcf7f91fcd90aaccc517d37969d4'),
    ('nfa-test_display_source_view_masks_credentials_partly_consumed_by_csi-7', 'tests.unit.core.test_primitives.test_display_source_view_masks_credentials_partly_consumed_by_csi', '7d5504aeec06f1a061251c8abdcd814875e37c09e8faf602917f4baa900b585a'),
    ('nfa-test_display_source_view_masks_credentials_partly_consumed_by_csi-8', 'tests.unit.core.test_primitives.test_display_source_view_masks_credentials_partly_consumed_by_csi', 'a1a0f5faccb3bc271b58a61292e4dc19a46fe779ca30ad48576818615f0e2649'),
    ('nfa-test_display_source_view_masks_credentials_partly_consumed_by_csi-9', 'tests.unit.core.test_primitives.test_display_source_view_masks_credentials_partly_consumed_by_csi', 'fb2eb85543a14b61ced60716e92d1222f0b087417c1f4404ffb25a4f176df0b5'),
    ('nfa-test_display_source_view_masks_credentials_partly_consumed_by_csi-10', 'tests.unit.core.test_primitives.test_display_source_view_masks_credentials_partly_consumed_by_csi', 'cdba337dc36eb33c154da79eb95fed6cb9c5b5f1610250f05ba14bd1b05bd376'),
    ('nfa-test_display_source_view_masks_credentials_partly_consumed_by_csi-11', 'tests.unit.core.test_primitives.test_display_source_view_masks_credentials_partly_consumed_by_csi', 'eb9df2ad7b4e36f965a10543df2c1f16d0ccf9ee0104ea491a9fb87e4162513f'),
    ('nfa-test_display_source_view_masks_credentials_partly_consumed_by_csi-12', 'tests.unit.core.test_primitives.test_display_source_view_masks_credentials_partly_consumed_by_csi', '9d98f42024cea8e3b8066a31034ef15be9695ff9c385572b041e66316db18bf7'),
    ('nfa-test_display_source_view_masks_credentials_partly_consumed_by_csi-13', 'tests.unit.core.test_primitives.test_display_source_view_masks_credentials_partly_consumed_by_csi', 'fead7dd3f7df12e3e0328408e31c45007aca23b6bc000847e8cbcdf10f7c084c'),
    ('nfa-test_display_source_view_masks_credentials_partly_consumed_by_csi-14', 'tests.unit.core.test_primitives.test_display_source_view_masks_credentials_partly_consumed_by_csi', '0c04454e46ef23416647c538084453bef25c0cb123805db223d215db647a151c'),
    ('nfa-test_display_source_view_masks_credentials_partly_consumed_by_csi-15', 'tests.unit.core.test_primitives.test_display_source_view_masks_credentials_partly_consumed_by_csi', 'f56833d40364a0844910d9c2125d009424e548224b6c129122cb505cb2f7ac28'),
    ('nfa-test_display_source_view_masks_only_surviving_characters_and_preserves_context-0', 'tests.unit.core.test_primitives.test_display_source_view_masks_only_surviving_characters_and_preserves_context', '44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a'),
    ('nfa-test_display_ten_million_removed_controls_do_not_build_per_control_state-0', 'tests.unit.core.test_primitives.test_display_ten_million_removed_controls_do_not_build_per_control_state', 'b12b7bd58f0f848c69c009157c5ce4a10f2d7f1cb46dd6e127fadec3be75c22b'),
    ('nfa-test_display_ten_million_removed_controls_do_not_build_per_control_state-1', 'tests.unit.core.test_primitives.test_display_ten_million_removed_controls_do_not_build_per_control_state', '7c370aa1a611185db043ce30176f8484ba977578e7049a8218485064fa7ab150'),
    ('nfa-test_display_ten_million_removed_controls_do_not_build_per_control_state-2', 'tests.unit.core.test_primitives.test_display_ten_million_removed_controls_do_not_build_per_control_state', '080dabb7252868d4e3f704eab51cdbf3510a147235400aaaea2e9475486e1cc0'),
    ('nfa-test_display_unions_canonical_and_source_only_masks-0', 'tests.unit.core.test_primitives.test_display_unions_canonical_and_source_only_masks', 'f52dcf4fcbd38b0763e8f2e68b3ce78fb675b04d679acf324525f19f663db0f8'),
    ('nfa-test_display_unions_canonical_and_source_only_masks-1', 'tests.unit.core.test_primitives.test_display_unions_canonical_and_source_only_masks', 'c01bb9000509a66f28a32deba50f0305ac5820798dc084af05e182671b99e1e8'),
    ('nfa-test_display_matches_legacy_output_for_supported_escape_corpus-0', 'tests.unit.cli.test_cli_helpers.test_display_matches_legacy_output_for_supported_escape_corpus', '44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a'),
)

CORPUS_CASES = (
    ('nfa-test_display_attribution_adjacent_colours_keep_long_context-0', 'tests.unit.core.test_primitives.test_display_attribution_adjacent_colours_keep_long_context', ()),
    ('nfa-test_display_attribution_budget_is_local_to_retries_and_parallel_calls-0', 'tests.unit.core.test_primitives.test_display_attribution_budget_is_local_to_retries_and_parallel_calls', ()),
    ('nfa-test_display_attribution_clipped_window_does_not_create_a_left_boundary-0', 'tests.unit.core.test_primitives.test_display_attribution_clipped_window_does_not_create_a_left_boundary', ()),
    ('nfa-test_display_attribution_covers_shared_rule_families-0', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'AAAAAAAA' + 'AAAAAAAA'), ('surface', 'sanitize'), ('value', 'ASIAAAAA' + 'AAAAAAAA' + 'AAAA'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-1', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'AAAAAAAA' + 'AAAAAAAA'), ('surface', 'sanitize'), ('value', 'AROAAAAA' + 'AAAAAAAA' + 'AAAA'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-2', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaaa'), ('surface', 'sanitize'), ('value', 'gho_aaaa' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-3', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa'), ('surface', 'sanitize'), ('value', 'github_p' + 'at_aaaaa' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaa'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-4', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa'), ('surface', 'sanitize'), ('value', 'glpat-aa' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaa'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-5', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa'), ('surface', 'sanitize'), ('value', 'sk_live_' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-6', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa'), ('surface', 'sanitize'), ('value', 'sk-proj-' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-7', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaa'), ('surface', 'sanitize'), ('value', 'AIzaaaaa' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa' + 'aa'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-8', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa'), ('surface', 'sanitize'), ('value', 'xoxb-aaa' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaa'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-9', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa'), ('surface', 'sanitize'), ('value', 'npm_aaaa' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaaa'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-10', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa'), ('surface', 'sanitize'), ('value', 'pypi-aaa' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaa'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-11', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'cccccccc'), ('surface', 'sanitize'), ('value', 'eyJaaaaa' + 'aaaaaaa.' + 'bbbbbbbb' + '.ccccccc' + 'c'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-12', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa'), ('surface', 'sanitize'), ('value', 'Bearer a' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaa'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-13', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'test-val' + 'ue-12345' + '6'), ('surface', 'sanitize'), ('value', 'password' + '=test-va' + 'lue-1234' + '56'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-14', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'test-val' + 'ue-12345' + '6'), ('surface', 'sanitize'), ('value', 'password' + ' is test' + '-value-1' + '23456'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-15', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'test-val' + 'ue-12345' + '6'), ('surface', 'sanitize'), ('value', 'https://' + 'user:tes' + 't-value-' + '123456@e' + 'xample.t' + 'est'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-16', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'AAAAAAAA' + 'AAAAAAAA'), ('surface', 'receipt'), ('value', 'ASIAAAAA' + 'AAAAAAAA' + 'AAAA'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-17', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'AAAAAAAA' + 'AAAAAAAA'), ('surface', 'receipt'), ('value', 'AROAAAAA' + 'AAAAAAAA' + 'AAAA'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-18', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaaa'), ('surface', 'receipt'), ('value', 'gho_aaaa' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-19', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa'), ('surface', 'receipt'), ('value', 'github_p' + 'at_aaaaa' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaa'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-20', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa'), ('surface', 'receipt'), ('value', 'glpat-aa' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaa'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-21', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa'), ('surface', 'receipt'), ('value', 'sk_live_' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-22', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa'), ('surface', 'receipt'), ('value', 'sk-proj-' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-23', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaa'), ('surface', 'receipt'), ('value', 'AIzaaaaa' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa' + 'aa'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-24', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa'), ('surface', 'receipt'), ('value', 'xoxb-aaa' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaa'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-25', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa'), ('surface', 'receipt'), ('value', 'npm_aaaa' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaaa'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-26', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa'), ('surface', 'receipt'), ('value', 'pypi-aaa' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaa'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-27', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'cccccccc'), ('surface', 'receipt'), ('value', 'eyJaaaaa' + 'aaaaaaa.' + 'bbbbbbbb' + '.ccccccc' + 'c'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-28', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa'), ('surface', 'receipt'), ('value', 'Bearer a' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaa'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-29', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'test-val' + 'ue-12345' + '6'), ('surface', 'receipt'), ('value', 'password' + '=test-va' + 'lue-1234' + '56'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-30', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'test-val' + 'ue-12345' + '6'), ('surface', 'receipt'), ('value', 'password' + ' is test' + '-value-1' + '23456'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-31', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'test-val' + 'ue-12345' + '6'), ('surface', 'receipt'), ('value', 'https://' + 'user:tes' + 't-value-' + '123456@e' + 'xample.t' + 'est'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-32', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'AAAAAAAA' + 'AAAAAAAA'), ('surface', 'guidance'), ('value', 'ASIAAAAA' + 'AAAAAAAA' + 'AAAA'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-33', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'AAAAAAAA' + 'AAAAAAAA'), ('surface', 'guidance'), ('value', 'AROAAAAA' + 'AAAAAAAA' + 'AAAA'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-34', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaaa'), ('surface', 'guidance'), ('value', 'gho_aaaa' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-35', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa'), ('surface', 'guidance'), ('value', 'github_p' + 'at_aaaaa' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaa'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-36', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa'), ('surface', 'guidance'), ('value', 'glpat-aa' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaa'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-37', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa'), ('surface', 'guidance'), ('value', 'sk_live_' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-38', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa'), ('surface', 'guidance'), ('value', 'sk-proj-' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-39', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaa'), ('surface', 'guidance'), ('value', 'AIzaaaaa' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa' + 'aa'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-40', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa'), ('surface', 'guidance'), ('value', 'xoxb-aaa' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaa'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-41', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa'), ('surface', 'guidance'), ('value', 'npm_aaaa' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaaa'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-42', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa'), ('surface', 'guidance'), ('value', 'pypi-aaa' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaa'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-43', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'cccccccc'), ('surface', 'guidance'), ('value', 'eyJaaaaa' + 'aaaaaaa.' + 'bbbbbbbb' + '.ccccccc' + 'c'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-44', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa'), ('surface', 'guidance'), ('value', 'Bearer a' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaa'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-45', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'test-val' + 'ue-12345' + '6'), ('surface', 'guidance'), ('value', 'password' + '=test-va' + 'lue-1234' + '56'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-46', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'test-val' + 'ue-12345' + '6'), ('surface', 'guidance'), ('value', 'password' + ' is test' + '-value-1' + '23456'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-47', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'test-val' + 'ue-12345' + '6'), ('surface', 'guidance'), ('value', 'https://' + 'user:tes' + 't-value-' + '123456@e' + 'xample.t' + 'est'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-48', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'AAAAAAAA' + 'AAAAAAAA'), ('surface', 'proposal'), ('value', 'ASIAAAAA' + 'AAAAAAAA' + 'AAAA'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-49', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'AAAAAAAA' + 'AAAAAAAA'), ('surface', 'proposal'), ('value', 'AROAAAAA' + 'AAAAAAAA' + 'AAAA'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-50', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaaa'), ('surface', 'proposal'), ('value', 'gho_aaaa' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-51', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa'), ('surface', 'proposal'), ('value', 'github_p' + 'at_aaaaa' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaa'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-52', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa'), ('surface', 'proposal'), ('value', 'glpat-aa' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaa'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-53', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa'), ('surface', 'proposal'), ('value', 'sk_live_' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-54', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa'), ('surface', 'proposal'), ('value', 'sk-proj-' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-55', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaa'), ('surface', 'proposal'), ('value', 'AIzaaaaa' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa' + 'aa'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-56', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa'), ('surface', 'proposal'), ('value', 'xoxb-aaa' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaa'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-57', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa'), ('surface', 'proposal'), ('value', 'npm_aaaa' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaaa'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-58', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa'), ('surface', 'proposal'), ('value', 'pypi-aaa' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaa'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-59', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'cccccccc'), ('surface', 'proposal'), ('value', 'eyJaaaaa' + 'aaaaaaa.' + 'bbbbbbbb' + '.ccccccc' + 'c'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-60', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa'), ('surface', 'proposal'), ('value', 'Bearer a' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaa'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-61', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'test-val' + 'ue-12345' + '6'), ('surface', 'proposal'), ('value', 'password' + '=test-va' + 'lue-1234' + '56'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-62', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'test-val' + 'ue-12345' + '6'), ('surface', 'proposal'), ('value', 'password' + ' is test' + '-value-1' + '23456'))),
    ('nfa-test_display_attribution_covers_shared_rule_families-63', 'tests.unit.core.test_primitives.test_display_attribution_covers_shared_rule_families', (('payload', 'test-val' + 'ue-12345' + '6'), ('surface', 'proposal'), ('value', 'https://' + 'user:tes' + 't-value-' + '123456@e' + 'xample.t' + 'est'))),
    ('nfa-test_display_attribution_detection_windows_keep_visible_whitespace-0', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_keep_visible_whitespace', ()),
    ('nfa-test_display_attribution_detection_windows_retry_after_large_gap_in_parallel-0', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_retry_after_large_gap_in_parallel', ()),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-0', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', (('control', '\x00'), ('count', 5000), ('surface', 'sanitize'))),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-1', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', (('control', '\x00'), ('count', 50000), ('surface', 'sanitize'))),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-2', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', (('control', '\r'), ('count', 5000), ('surface', 'sanitize'))),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-3', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', (('control', '\r'), ('count', 50000), ('surface', 'sanitize'))),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-4', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', (('control', '\x7f'), ('count', 5000), ('surface', 'sanitize'))),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-5', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', (('control', '\x7f'), ('count', 50000), ('surface', 'sanitize'))),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-6', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', (('control', '\x85'), ('count', 5000), ('surface', 'sanitize'))),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-7', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', (('control', '\x85'), ('count', 50000), ('surface', 'sanitize'))),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-8', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', (('control', '\x00'), ('count', 5000), ('surface', 'receipt'))),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-9', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', (('control', '\x00'), ('count', 50000), ('surface', 'receipt'))),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-10', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', (('control', '\r'), ('count', 5000), ('surface', 'receipt'))),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-11', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', (('control', '\r'), ('count', 50000), ('surface', 'receipt'))),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-12', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', (('control', '\x7f'), ('count', 5000), ('surface', 'receipt'))),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-13', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', (('control', '\x7f'), ('count', 50000), ('surface', 'receipt'))),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-14', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', (('control', '\x85'), ('count', 5000), ('surface', 'receipt'))),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-15', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', (('control', '\x85'), ('count', 50000), ('surface', 'receipt'))),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-16', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', (('control', '\x00'), ('count', 5000), ('surface', 'guidance'))),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-17', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', (('control', '\x00'), ('count', 50000), ('surface', 'guidance'))),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-18', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', (('control', '\r'), ('count', 5000), ('surface', 'guidance'))),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-19', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', (('control', '\r'), ('count', 50000), ('surface', 'guidance'))),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-20', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', (('control', '\x7f'), ('count', 5000), ('surface', 'guidance'))),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-21', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', (('control', '\x7f'), ('count', 50000), ('surface', 'guidance'))),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-22', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', (('control', '\x85'), ('count', 5000), ('surface', 'guidance'))),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-23', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', (('control', '\x85'), ('count', 50000), ('surface', 'guidance'))),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-24', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', (('control', '\x00'), ('count', 5000), ('surface', 'proposal'))),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-25', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', (('control', '\x00'), ('count', 50000), ('surface', 'proposal'))),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-26', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', (('control', '\r'), ('count', 5000), ('surface', 'proposal'))),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-27', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', (('control', '\r'), ('count', 50000), ('surface', 'proposal'))),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-28', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', (('control', '\x7f'), ('count', 5000), ('surface', 'proposal'))),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-29', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', (('control', '\x7f'), ('count', 50000), ('surface', 'proposal'))),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-30', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', (('control', '\x85'), ('count', 5000), ('surface', 'proposal'))),
    ('nfa-test_display_attribution_detection_windows_span_removed_control_gaps-31', 'tests.unit.core.test_primitives.test_display_attribution_detection_windows_span_removed_control_gaps', (('control', '\x85'), ('count', 50000), ('surface', 'proposal'))),
    ('nfa-test_display_attribution_exhausted_window_does_not_poison_later_window-0', 'tests.unit.core.test_primitives.test_display_attribution_exhausted_window_does_not_poison_later_window', ()),
    ('nfa-test_display_attribution_fallback_keeps_carried_starts-0', 'tests.unit.core.test_primitives.test_display_attribution_fallback_keeps_carried_starts', (('surface', 'sanitize'),)),
    ('nfa-test_display_attribution_fallback_keeps_carried_starts-1', 'tests.unit.core.test_primitives.test_display_attribution_fallback_keeps_carried_starts', (('surface', 'receipt'),)),
    ('nfa-test_display_attribution_fallback_keeps_carried_starts-2', 'tests.unit.core.test_primitives.test_display_attribution_fallback_keeps_carried_starts', (('surface', 'guidance'),)),
    ('nfa-test_display_attribution_fallback_keeps_carried_starts-3', 'tests.unit.core.test_primitives.test_display_attribution_fallback_keeps_carried_starts', (('surface', 'proposal'),)),
    ('nfa-test_display_attribution_fallback_preserves_ordinary_boundary_and_flags-0', 'tests.unit.core.test_primitives.test_display_attribution_fallback_preserves_ordinary_boundary_and_flags', (('plain', 'xAKIAAAA' + 'AAAAAAAA' + 'AAAAA'), ('surface', 'sanitize'))),
    ('nfa-test_display_attribution_fallback_preserves_ordinary_boundary_and_flags-1', 'tests.unit.core.test_primitives.test_display_attribution_fallback_preserves_ordinary_boundary_and_flags', (('plain', 'xAKIAAAA' + 'AAAAAAAA' + 'AAAAA'), ('surface', 'receipt'))),
    ('nfa-test_display_attribution_fallback_preserves_ordinary_boundary_and_flags-2', 'tests.unit.core.test_primitives.test_display_attribution_fallback_preserves_ordinary_boundary_and_flags', (('plain', 'xAKIAAAA' + 'AAAAAAAA' + 'AAAAA'), ('surface', 'guidance'))),
    ('nfa-test_display_attribution_fallback_preserves_ordinary_boundary_and_flags-3', 'tests.unit.core.test_primitives.test_display_attribution_fallback_preserves_ordinary_boundary_and_flags', (('plain', 'xAKIAAAA' + 'AAAAAAAA' + 'AAAAA'), ('surface', 'proposal'))),
    ('nfa-test_display_attribution_fallback_preserves_ordinary_boundary_and_flags-4', 'tests.unit.core.test_primitives.test_display_attribution_fallback_preserves_ordinary_boundary_and_flags', (('plain', 'KBearer ' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa'), ('surface', 'sanitize'))),
    ('nfa-test_display_attribution_fallback_preserves_ordinary_boundary_and_flags-5', 'tests.unit.core.test_primitives.test_display_attribution_fallback_preserves_ordinary_boundary_and_flags', (('plain', 'KBearer ' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa'), ('surface', 'receipt'))),
    ('nfa-test_display_attribution_fallback_preserves_ordinary_boundary_and_flags-6', 'tests.unit.core.test_primitives.test_display_attribution_fallback_preserves_ordinary_boundary_and_flags', (('plain', 'KBearer ' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa'), ('surface', 'guidance'))),
    ('nfa-test_display_attribution_fallback_preserves_ordinary_boundary_and_flags-7', 'tests.unit.core.test_primitives.test_display_attribution_fallback_preserves_ordinary_boundary_and_flags', (('plain', 'KBearer ' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa'), ('surface', 'proposal'))),
    ('nfa-test_display_attribution_hidden_only_credential_does_not_mask_visible_context-0', 'tests.unit.core.test_primitives.test_display_attribution_hidden_only_credential_does_not_mask_visible_context', ()),
    ('nfa-test_display_attribution_long_benign_colour_runs_keep_parity-0', 'tests.unit.core.test_primitives.test_display_attribution_long_benign_colour_runs_keep_parity', (('count', 1),)),
    ('nfa-test_display_attribution_long_benign_colour_runs_keep_parity-1', 'tests.unit.core.test_primitives.test_display_attribution_long_benign_colour_runs_keep_parity', (('count', 3),)),
    ('nfa-test_display_attribution_long_benign_colour_runs_keep_parity-2', 'tests.unit.core.test_primitives.test_display_attribution_long_benign_colour_runs_keep_parity', (('count', 6),)),
    ('nfa-test_display_attribution_masks_overlapping_ordinary_credentials-0', 'tests.unit.core.test_primitives.test_display_attribution_masks_overlapping_ordinary_credentials', (('family', 'jwt'), ('surface', 'sanitize'))),
    ('nfa-test_display_attribution_masks_overlapping_ordinary_credentials-1', 'tests.unit.core.test_primitives.test_display_attribution_masks_overlapping_ordinary_credentials', (('family', 'jwt'), ('surface', 'receipt'))),
    ('nfa-test_display_attribution_masks_overlapping_ordinary_credentials-2', 'tests.unit.core.test_primitives.test_display_attribution_masks_overlapping_ordinary_credentials', (('family', 'jwt'), ('surface', 'guidance'))),
    ('nfa-test_display_attribution_masks_overlapping_ordinary_credentials-3', 'tests.unit.core.test_primitives.test_display_attribution_masks_overlapping_ordinary_credentials', (('family', 'jwt'), ('surface', 'proposal'))),
    ('nfa-test_display_attribution_masks_overlapping_ordinary_credentials-4', 'tests.unit.core.test_primitives.test_display_attribution_masks_overlapping_ordinary_credentials', (('family', 'vcs'), ('surface', 'sanitize'))),
    ('nfa-test_display_attribution_masks_overlapping_ordinary_credentials-5', 'tests.unit.core.test_primitives.test_display_attribution_masks_overlapping_ordinary_credentials', (('family', 'vcs'), ('surface', 'receipt'))),
    ('nfa-test_display_attribution_masks_overlapping_ordinary_credentials-6', 'tests.unit.core.test_primitives.test_display_attribution_masks_overlapping_ordinary_credentials', (('family', 'vcs'), ('surface', 'guidance'))),
    ('nfa-test_display_attribution_masks_overlapping_ordinary_credentials-7', 'tests.unit.core.test_primitives.test_display_attribution_masks_overlapping_ordinary_credentials', (('family', 'vcs'), ('surface', 'proposal'))),
    ('nfa-test_display_attribution_overlaps_and_fallback_are_isolated_in_parallel-0', 'tests.unit.core.test_primitives.test_display_attribution_overlaps_and_fallback_are_isolated_in_parallel', ()),
    ('nfa-test_display_attribution_preserves_ordinary_left_boundary-0', 'tests.unit.core.test_primitives.test_display_attribution_preserves_ordinary_left_boundary', (('suffix', ''),)),
    ('nfa-test_display_attribution_preserves_ordinary_left_boundary-1', 'tests.unit.core.test_primitives.test_display_attribution_preserves_ordinary_left_boundary', (('suffix', '\x1b[31m'),)),
    ('nfa-test_display_attribution_widths_and_unknown_grammars_fail_conservatively-0', 'tests.unit.core.test_primitives.test_display_attribution_widths_and_unknown_grammars_fail_conservatively', ()),
    ('nfa-test_display_boundaries_are_local_to_parallel_calls_and_retries-0', 'tests.unit.core.test_primitives.test_display_boundaries_are_local_to_parallel_calls_and_retries', ()),
    ('nfa-test_display_boundary_detection_keeps_secrets_split_by_inner_controls_masked-0', 'tests.unit.core.test_primitives.test_display_boundary_detection_keeps_secrets_split_by_inner_controls_masked', ()),
    ('nfa-test_display_boundary_detection_uses_shared_secret_families-0', 'tests.unit.core.test_primitives.test_display_boundary_detection_uses_shared_secret_families', (('payload', 'AAAAAAAA' + 'AAAAAAAA'), ('value', 'ASIAAAAA' + 'AAAAAAAA' + 'AAAA'))),
    ('nfa-test_display_boundary_detection_uses_shared_secret_families-1', 'tests.unit.core.test_primitives.test_display_boundary_detection_uses_shared_secret_families', (('payload', 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaaa'), ('value', 'ghp_aaaa' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaaaaaaa'))),
    ('nfa-test_display_boundary_detection_uses_shared_secret_families-2', 'tests.unit.core.test_primitives.test_display_boundary_detection_uses_shared_secret_families', (('payload', 'Ab1Ab1Ab' + '1Ab1Ab1A' + 'b1Ab1Ab1' + 'Ab1Ab1Ab' + '1Ab1'), ('value', 'sk-proj-' + 'Ab1Ab1Ab' + '1Ab1Ab1A' + 'b1Ab1Ab1' + 'Ab1Ab1Ab' + '1Ab1'))),
    ('nfa-test_display_boundary_detection_uses_shared_secret_families-3', 'tests.unit.core.test_primitives.test_display_boundary_detection_uses_shared_secret_families', (('payload', 'test-val' + 'ue-12345' + '6'), ('value', 'token=te' + 'st-value' + '-123456'))),
    ('nfa-test_display_boundary_detection_uses_shared_secret_families-4', 'tests.unit.core.test_primitives.test_display_boundary_detection_uses_shared_secret_families', (('payload', 'aaaaaaaa' + 'aaaaaaaa' + 'aaaa'), ('value', 'Bearer a' + 'aaaaaaaa' + 'aaaaaaaa' + 'aaa'))),
    ('nfa-test_display_boundary_detection_uses_shared_secret_families-5', 'tests.unit.core.test_primitives.test_display_boundary_detection_uses_shared_secret_families', (('payload', 'test-val' + 'ue-12345' + '6'), ('value', 'https://' + 'user:tes' + 't-value-' + '123456@e' + 'xample.t' + 'est'))),
    ('nfa-test_display_boundary_detection_uses_shared_secret_families-6', 'tests.unit.core.test_primitives.test_display_boundary_detection_uses_shared_secret_families', (('payload', 'body'), ('value', '-----BEG' + 'IN PRIVA' + 'TE KEY--' + '---body'))),
    ('nfa-test_display_boundary_mask_preserves_legacy_kind_bytes_and_plain_baseline-0', 'tests.unit.core.test_primitives.test_display_boundary_mask_preserves_legacy_kind_bytes_and_plain_baseline', ()),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-0', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', (('prefix', '\x1b[?\x07:m'), ('surface', 'sanitize'))),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-1', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', (('prefix', '\x9b?\x07:m'), ('surface', 'sanitize'))),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-2', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', (('prefix', '\x1b(\x07B'), ('surface', 'sanitize'))),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-3', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', (('prefix', '\x1bX1\x072'), ('surface', 'sanitize'))),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-4', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', (('prefix', '\x1b^1\x072'), ('surface', 'sanitize'))),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-5', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', (('prefix', '\x1b_1\x072'), ('surface', 'sanitize'))),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-6', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', (('prefix', '\x981\x072'), ('surface', 'sanitize'))),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-7', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', (('prefix', '\x9e1\x072'), ('surface', 'sanitize'))),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-8', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', (('prefix', '\x9f1\x072'), ('surface', 'sanitize'))),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-9', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', (('prefix', '\x901\x072'), ('surface', 'sanitize'))),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-10', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', (('prefix', '\x9d1\x072'), ('surface', 'sanitize'))),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-11', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', (('prefix', '\x1b[?\x07:m'), ('surface', 'receipt'))),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-12', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', (('prefix', '\x9b?\x07:m'), ('surface', 'receipt'))),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-13', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', (('prefix', '\x1b(\x07B'), ('surface', 'receipt'))),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-14', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', (('prefix', '\x1bX1\x072'), ('surface', 'receipt'))),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-15', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', (('prefix', '\x1b^1\x072'), ('surface', 'receipt'))),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-16', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', (('prefix', '\x1b_1\x072'), ('surface', 'receipt'))),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-17', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', (('prefix', '\x981\x072'), ('surface', 'receipt'))),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-18', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', (('prefix', '\x9e1\x072'), ('surface', 'receipt'))),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-19', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', (('prefix', '\x9f1\x072'), ('surface', 'receipt'))),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-20', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', (('prefix', '\x901\x072'), ('surface', 'receipt'))),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-21', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', (('prefix', '\x9d1\x072'), ('surface', 'receipt'))),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-22', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', (('prefix', '\x1b[?\x07:m'), ('surface', 'guidance'))),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-23', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', (('prefix', '\x9b?\x07:m'), ('surface', 'guidance'))),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-24', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', (('prefix', '\x1b(\x07B'), ('surface', 'guidance'))),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-25', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', (('prefix', '\x1bX1\x072'), ('surface', 'guidance'))),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-26', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', (('prefix', '\x1b^1\x072'), ('surface', 'guidance'))),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-27', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', (('prefix', '\x1b_1\x072'), ('surface', 'guidance'))),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-28', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', (('prefix', '\x981\x072'), ('surface', 'guidance'))),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-29', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', (('prefix', '\x9e1\x072'), ('surface', 'guidance'))),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-30', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', (('prefix', '\x9f1\x072'), ('surface', 'guidance'))),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-31', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', (('prefix', '\x901\x072'), ('surface', 'guidance'))),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-32', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', (('prefix', '\x9d1\x072'), ('surface', 'guidance'))),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-33', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', (('prefix', '\x1b[?\x07:m'), ('surface', 'proposal'))),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-34', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', (('prefix', '\x9b?\x07:m'), ('surface', 'proposal'))),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-35', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', (('prefix', '\x1b(\x07B'), ('surface', 'proposal'))),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-36', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', (('prefix', '\x1bX1\x072'), ('surface', 'proposal'))),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-37', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', (('prefix', '\x1b^1\x072'), ('surface', 'proposal'))),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-38', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', (('prefix', '\x1b_1\x072'), ('surface', 'proposal'))),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-39', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', (('prefix', '\x981\x072'), ('surface', 'proposal'))),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-40', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', (('prefix', '\x9e1\x072'), ('surface', 'proposal'))),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-41', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', (('prefix', '\x9f1\x072'), ('surface', 'proposal'))),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-42', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', (('prefix', '\x901\x072'), ('surface', 'proposal'))),
    ('nfa-test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers-43', 'tests.unit.core.test_primitives.test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers', (('prefix', '\x9d1\x072'), ('surface', 'proposal'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-0', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'aws'), ('inner', '\r'), ('prefix', '\x1b['), ('surface', 'sanitize'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-1', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'aws'), ('inner', '\r'), ('prefix', '\x1b[1'), ('surface', 'sanitize'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-2', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'aws'), ('inner', '\x00'), ('prefix', '\x1b['), ('surface', 'sanitize'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-3', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'aws'), ('inner', '\x00'), ('prefix', '\x1b[1'), ('surface', 'sanitize'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-4', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'aws'), ('inner', '\x7f'), ('prefix', '\x1b['), ('surface', 'sanitize'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-5', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'aws'), ('inner', '\x7f'), ('prefix', '\x1b[1'), ('surface', 'sanitize'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-6', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'aws'), ('inner', '\x85'), ('prefix', '\x1b['), ('surface', 'sanitize'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-7', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'aws'), ('inner', '\x85'), ('prefix', '\x1b[1'), ('surface', 'sanitize'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-8', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'aws'), ('inner', '\x1b[31m'), ('prefix', '\x1b['), ('surface', 'sanitize'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-9', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'aws'), ('inner', '\x1b[31m'), ('prefix', '\x1b[1'), ('surface', 'sanitize'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-10', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'github'), ('inner', '\r'), ('prefix', '\x1b['), ('surface', 'sanitize'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-11', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'github'), ('inner', '\r'), ('prefix', '\x1b[1'), ('surface', 'sanitize'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-12', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'github'), ('inner', '\x00'), ('prefix', '\x1b['), ('surface', 'sanitize'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-13', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'github'), ('inner', '\x00'), ('prefix', '\x1b[1'), ('surface', 'sanitize'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-14', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'github'), ('inner', '\x7f'), ('prefix', '\x1b['), ('surface', 'sanitize'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-15', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'github'), ('inner', '\x7f'), ('prefix', '\x1b[1'), ('surface', 'sanitize'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-16', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'github'), ('inner', '\x85'), ('prefix', '\x1b['), ('surface', 'sanitize'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-17', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'github'), ('inner', '\x85'), ('prefix', '\x1b[1'), ('surface', 'sanitize'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-18', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'github'), ('inner', '\x1b[31m'), ('prefix', '\x1b['), ('surface', 'sanitize'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-19', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'github'), ('inner', '\x1b[31m'), ('prefix', '\x1b[1'), ('surface', 'sanitize'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-20', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'aws'), ('inner', '\r'), ('prefix', '\x1b['), ('surface', 'receipt'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-21', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'aws'), ('inner', '\r'), ('prefix', '\x1b[1'), ('surface', 'receipt'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-22', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'aws'), ('inner', '\x00'), ('prefix', '\x1b['), ('surface', 'receipt'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-23', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'aws'), ('inner', '\x00'), ('prefix', '\x1b[1'), ('surface', 'receipt'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-24', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'aws'), ('inner', '\x7f'), ('prefix', '\x1b['), ('surface', 'receipt'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-25', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'aws'), ('inner', '\x7f'), ('prefix', '\x1b[1'), ('surface', 'receipt'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-26', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'aws'), ('inner', '\x85'), ('prefix', '\x1b['), ('surface', 'receipt'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-27', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'aws'), ('inner', '\x85'), ('prefix', '\x1b[1'), ('surface', 'receipt'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-28', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'aws'), ('inner', '\x1b[31m'), ('prefix', '\x1b['), ('surface', 'receipt'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-29', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'aws'), ('inner', '\x1b[31m'), ('prefix', '\x1b[1'), ('surface', 'receipt'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-30', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'github'), ('inner', '\r'), ('prefix', '\x1b['), ('surface', 'receipt'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-31', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'github'), ('inner', '\r'), ('prefix', '\x1b[1'), ('surface', 'receipt'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-32', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'github'), ('inner', '\x00'), ('prefix', '\x1b['), ('surface', 'receipt'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-33', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'github'), ('inner', '\x00'), ('prefix', '\x1b[1'), ('surface', 'receipt'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-34', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'github'), ('inner', '\x7f'), ('prefix', '\x1b['), ('surface', 'receipt'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-35', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'github'), ('inner', '\x7f'), ('prefix', '\x1b[1'), ('surface', 'receipt'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-36', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'github'), ('inner', '\x85'), ('prefix', '\x1b['), ('surface', 'receipt'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-37', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'github'), ('inner', '\x85'), ('prefix', '\x1b[1'), ('surface', 'receipt'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-38', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'github'), ('inner', '\x1b[31m'), ('prefix', '\x1b['), ('surface', 'receipt'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-39', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'github'), ('inner', '\x1b[31m'), ('prefix', '\x1b[1'), ('surface', 'receipt'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-40', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'aws'), ('inner', '\r'), ('prefix', '\x1b['), ('surface', 'guidance'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-41', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'aws'), ('inner', '\r'), ('prefix', '\x1b[1'), ('surface', 'guidance'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-42', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'aws'), ('inner', '\x00'), ('prefix', '\x1b['), ('surface', 'guidance'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-43', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'aws'), ('inner', '\x00'), ('prefix', '\x1b[1'), ('surface', 'guidance'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-44', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'aws'), ('inner', '\x7f'), ('prefix', '\x1b['), ('surface', 'guidance'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-45', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'aws'), ('inner', '\x7f'), ('prefix', '\x1b[1'), ('surface', 'guidance'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-46', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'aws'), ('inner', '\x85'), ('prefix', '\x1b['), ('surface', 'guidance'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-47', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'aws'), ('inner', '\x85'), ('prefix', '\x1b[1'), ('surface', 'guidance'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-48', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'aws'), ('inner', '\x1b[31m'), ('prefix', '\x1b['), ('surface', 'guidance'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-49', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'aws'), ('inner', '\x1b[31m'), ('prefix', '\x1b[1'), ('surface', 'guidance'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-50', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'github'), ('inner', '\r'), ('prefix', '\x1b['), ('surface', 'guidance'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-51', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'github'), ('inner', '\r'), ('prefix', '\x1b[1'), ('surface', 'guidance'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-52', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'github'), ('inner', '\x00'), ('prefix', '\x1b['), ('surface', 'guidance'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-53', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'github'), ('inner', '\x00'), ('prefix', '\x1b[1'), ('surface', 'guidance'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-54', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'github'), ('inner', '\x7f'), ('prefix', '\x1b['), ('surface', 'guidance'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-55', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'github'), ('inner', '\x7f'), ('prefix', '\x1b[1'), ('surface', 'guidance'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-56', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'github'), ('inner', '\x85'), ('prefix', '\x1b['), ('surface', 'guidance'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-57', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'github'), ('inner', '\x85'), ('prefix', '\x1b[1'), ('surface', 'guidance'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-58', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'github'), ('inner', '\x1b[31m'), ('prefix', '\x1b['), ('surface', 'guidance'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-59', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'github'), ('inner', '\x1b[31m'), ('prefix', '\x1b[1'), ('surface', 'guidance'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-60', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'aws'), ('inner', '\r'), ('prefix', '\x1b['), ('surface', 'proposal'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-61', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'aws'), ('inner', '\r'), ('prefix', '\x1b[1'), ('surface', 'proposal'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-62', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'aws'), ('inner', '\x00'), ('prefix', '\x1b['), ('surface', 'proposal'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-63', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'aws'), ('inner', '\x00'), ('prefix', '\x1b[1'), ('surface', 'proposal'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-64', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'aws'), ('inner', '\x7f'), ('prefix', '\x1b['), ('surface', 'proposal'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-65', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'aws'), ('inner', '\x7f'), ('prefix', '\x1b[1'), ('surface', 'proposal'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-66', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'aws'), ('inner', '\x85'), ('prefix', '\x1b['), ('surface', 'proposal'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-67', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'aws'), ('inner', '\x85'), ('prefix', '\x1b[1'), ('surface', 'proposal'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-68', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'aws'), ('inner', '\x1b[31m'), ('prefix', '\x1b['), ('surface', 'proposal'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-69', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'aws'), ('inner', '\x1b[31m'), ('prefix', '\x1b[1'), ('surface', 'proposal'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-70', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'github'), ('inner', '\r'), ('prefix', '\x1b['), ('surface', 'proposal'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-71', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'github'), ('inner', '\r'), ('prefix', '\x1b[1'), ('surface', 'proposal'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-72', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'github'), ('inner', '\x00'), ('prefix', '\x1b['), ('surface', 'proposal'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-73', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'github'), ('inner', '\x00'), ('prefix', '\x1b[1'), ('surface', 'proposal'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-74', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'github'), ('inner', '\x7f'), ('prefix', '\x1b['), ('surface', 'proposal'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-75', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'github'), ('inner', '\x7f'), ('prefix', '\x1b[1'), ('surface', 'proposal'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-76', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'github'), ('inner', '\x85'), ('prefix', '\x1b['), ('surface', 'proposal'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-77', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'github'), ('inner', '\x85'), ('prefix', '\x1b[1'), ('surface', 'proposal'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-78', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'github'), ('inner', '\x1b[31m'), ('prefix', '\x1b['), ('surface', 'proposal'))),
    ('nfa-test_display_deleted_view_masks_consumed_prefix_with_internal_control-79', 'tests.unit.core.test_primitives.test_display_deleted_view_masks_consumed_prefix_with_internal_control', (('family', 'github'), ('inner', '\x1b[31m'), ('prefix', '\x1b[1'), ('surface', 'proposal'))),
    ('nfa-test_display_deleted_view_preserves_bel_termination_and_nonsecret_parity-0', 'tests.unit.core.test_primitives.test_display_deleted_view_preserves_bel_termination_and_nonsecret_parity', (('introduc' + 'er', '\x1b]'),)),
    ('nfa-test_display_deleted_view_preserves_bel_termination_and_nonsecret_parity-1', 'tests.unit.core.test_primitives.test_display_deleted_view_preserves_bel_termination_and_nonsecret_parity', (('introduc' + 'er', '\x1bP'),)),
    ('nfa-test_display_does_not_orphan_value_after_guarding_secret_key_context-0', 'tests.unit.core.test_primitives.test_display_does_not_orphan_value_after_guarding_secret_key_context', (('surface', 'sanitize'),)),
    ('nfa-test_display_does_not_orphan_value_after_guarding_secret_key_context-1', 'tests.unit.core.test_primitives.test_display_does_not_orphan_value_after_guarding_secret_key_context', (('surface', 'receipt'),)),
    ('nfa-test_display_does_not_orphan_value_after_guarding_secret_key_context-2', 'tests.unit.core.test_primitives.test_display_does_not_orphan_value_after_guarding_secret_key_context', (('surface', 'guidance'),)),
    ('nfa-test_display_does_not_orphan_value_after_guarding_secret_key_context-3', 'tests.unit.core.test_primitives.test_display_does_not_orphan_value_after_guarding_secret_key_context', (('surface', 'proposal'),)),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-0', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', '\x1bP'), ('surface', 'sanitize'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-1', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', '\x1bP\x1b[31m'), ('surface', 'sanitize'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-2', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', 'note\x1b]\x1bP'), ('surface', 'sanitize'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-3', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', 'note\x1b]0;' + 'title\x1b7'), ('surface', 'sanitize'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-4', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', '\x1bP\x9b31m'), ('surface', 'sanitize'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-5', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', '\x1bP$q'), ('surface', 'sanitize'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-6', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', '\x1bP1;2q'), ('surface', 'sanitize'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-7', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', '\x901;2q'), ('surface', 'sanitize'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-8', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', '\x1b(B'), ('surface', 'sanitize'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-9', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', 'note\x1bN'), ('surface', 'sanitize'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-10', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', 'note\x1bO'), ('surface', 'sanitize'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-11', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', 'note\x1bM'), ('surface', 'sanitize'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-12', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', 'note\x1b7'), ('surface', 'sanitize'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-13', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', 'note\x1b8'), ('surface', 'sanitize'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-14', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', 'note\x1bc'), ('surface', 'sanitize'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-15', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', '\x1bX'), ('surface', 'sanitize'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-16', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', '\x1b^'), ('surface', 'sanitize'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-17', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', '\x1b_'), ('surface', 'sanitize'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-18', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', 'note\x1b?'), ('surface', 'sanitize'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-19', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', 'note\x1b[12' + ';\x00'), ('surface', 'sanitize'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-20', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', '\x1bP'), ('surface', 'receipt'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-21', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', '\x1bP\x1b[31m'), ('surface', 'receipt'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-22', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', 'note\x1b]\x1bP'), ('surface', 'receipt'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-23', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', 'note\x1b]0;' + 'title\x1b7'), ('surface', 'receipt'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-24', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', '\x1bP\x9b31m'), ('surface', 'receipt'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-25', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', '\x1bP$q'), ('surface', 'receipt'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-26', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', '\x1bP1;2q'), ('surface', 'receipt'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-27', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', '\x901;2q'), ('surface', 'receipt'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-28', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', '\x1b(B'), ('surface', 'receipt'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-29', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', 'note\x1bN'), ('surface', 'receipt'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-30', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', 'note\x1bO'), ('surface', 'receipt'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-31', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', 'note\x1bM'), ('surface', 'receipt'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-32', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', 'note\x1b7'), ('surface', 'receipt'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-33', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', 'note\x1b8'), ('surface', 'receipt'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-34', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', 'note\x1bc'), ('surface', 'receipt'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-35', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', '\x1bX'), ('surface', 'receipt'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-36', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', '\x1b^'), ('surface', 'receipt'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-37', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', '\x1b_'), ('surface', 'receipt'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-38', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', 'note\x1b?'), ('surface', 'receipt'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-39', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', 'note\x1b[12' + ';\x00'), ('surface', 'receipt'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-40', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', '\x1bP'), ('surface', 'guidance'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-41', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', '\x1bP\x1b[31m'), ('surface', 'guidance'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-42', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', 'note\x1b]\x1bP'), ('surface', 'guidance'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-43', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', 'note\x1b]0;' + 'title\x1b7'), ('surface', 'guidance'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-44', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', '\x1bP\x9b31m'), ('surface', 'guidance'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-45', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', '\x1bP$q'), ('surface', 'guidance'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-46', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', '\x1bP1;2q'), ('surface', 'guidance'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-47', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', '\x901;2q'), ('surface', 'guidance'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-48', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', '\x1b(B'), ('surface', 'guidance'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-49', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', 'note\x1bN'), ('surface', 'guidance'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-50', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', 'note\x1bO'), ('surface', 'guidance'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-51', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', 'note\x1bM'), ('surface', 'guidance'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-52', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', 'note\x1b7'), ('surface', 'guidance'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-53', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', 'note\x1b8'), ('surface', 'guidance'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-54', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', 'note\x1bc'), ('surface', 'guidance'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-55', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', '\x1bX'), ('surface', 'guidance'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-56', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', '\x1b^'), ('surface', 'guidance'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-57', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', '\x1b_'), ('surface', 'guidance'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-58', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', 'note\x1b?'), ('surface', 'guidance'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-59', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', 'note\x1b[12' + ';\x00'), ('surface', 'guidance'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-60', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', '\x1bP'), ('surface', 'proposal'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-61', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', '\x1bP\x1b[31m'), ('surface', 'proposal'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-62', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', 'note\x1b]\x1bP'), ('surface', 'proposal'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-63', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', 'note\x1b]0;' + 'title\x1b7'), ('surface', 'proposal'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-64', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', '\x1bP\x9b31m'), ('surface', 'proposal'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-65', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', '\x1bP$q'), ('surface', 'proposal'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-66', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', '\x1bP1;2q'), ('surface', 'proposal'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-67', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', '\x901;2q'), ('surface', 'proposal'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-68', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', '\x1b(B'), ('surface', 'proposal'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-69', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', 'note\x1bN'), ('surface', 'proposal'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-70', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', 'note\x1bO'), ('surface', 'proposal'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-71', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', 'note\x1bM'), ('surface', 'proposal'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-72', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', 'note\x1b7'), ('surface', 'proposal'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-73', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', 'note\x1b8'), ('surface', 'proposal'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-74', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', 'note\x1bc'), ('surface', 'proposal'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-75', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', '\x1bX'), ('surface', 'proposal'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-76', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', '\x1b^'), ('surface', 'proposal'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-77', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', '\x1b_'), ('surface', 'proposal'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-78', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', 'note\x1b?'), ('surface', 'proposal'))),
    ('nfa-test_display_escape_boundaries_mask_secrets_on_every_surface-79', 'tests.unit.core.test_primitives.test_display_escape_boundaries_mask_secrets_on_every_surface', (('prefix', 'note\x1b[12' + ';\x00'), ('surface', 'proposal'))),
    ('nfa-test_display_pem_extents_cover_differently_labelled_nested_body-0', 'tests.unit.core.test_primitives.test_display_pem_extents_cover_differently_labelled_nested_body', (('label', 'EC'), ('surface', 'sanitize'))),
    ('nfa-test_display_pem_extents_cover_differently_labelled_nested_body-1', 'tests.unit.core.test_primitives.test_display_pem_extents_cover_differently_labelled_nested_body', (('label', 'EC'), ('surface', 'receipt'))),
    ('nfa-test_display_pem_extents_cover_differently_labelled_nested_body-2', 'tests.unit.core.test_primitives.test_display_pem_extents_cover_differently_labelled_nested_body', (('label', 'EC'), ('surface', 'guidance'))),
    ('nfa-test_display_pem_extents_cover_differently_labelled_nested_body-3', 'tests.unit.core.test_primitives.test_display_pem_extents_cover_differently_labelled_nested_body', (('label', 'EC'), ('surface', 'proposal'))),
    ('nfa-test_display_pem_extents_cover_differently_labelled_nested_body-4', 'tests.unit.core.test_primitives.test_display_pem_extents_cover_differently_labelled_nested_body', (('label', 'OPENSSH'), ('surface', 'sanitize'))),
    ('nfa-test_display_pem_extents_cover_differently_labelled_nested_body-5', 'tests.unit.core.test_primitives.test_display_pem_extents_cover_differently_labelled_nested_body', (('label', 'OPENSSH'), ('surface', 'receipt'))),
    ('nfa-test_display_pem_extents_cover_differently_labelled_nested_body-6', 'tests.unit.core.test_primitives.test_display_pem_extents_cover_differently_labelled_nested_body', (('label', 'OPENSSH'), ('surface', 'guidance'))),
    ('nfa-test_display_pem_extents_cover_differently_labelled_nested_body-7', 'tests.unit.core.test_primitives.test_display_pem_extents_cover_differently_labelled_nested_body', (('label', 'OPENSSH'), ('surface', 'proposal'))),
    ('nfa-test_display_preserves_url_context_and_masks_overlapping_secret_rules-0', 'tests.unit.core.test_primitives.test_display_preserves_url_context_and_masks_overlapping_secret_rules', ()),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-0', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1'), ('introduc' + 'er', '\x1bP'), ('surface', 'sanitize'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-1', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1'), ('introduc' + 'er', '\x1b]'), ('surface', 'sanitize'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-2', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1'), ('introduc' + 'er', '\x1bX'), ('surface', 'sanitize'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-3', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1'), ('introduc' + 'er', '\x1b^'), ('surface', 'sanitize'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-4', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1'), ('introduc' + 'er', '\x1b_'), ('surface', 'sanitize'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-5', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1'), ('introduc' + 'er', '\x90'), ('surface', 'sanitize'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-6', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1'), ('introduc' + 'er', '\x98'), ('surface', 'sanitize'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-7', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1'), ('introduc' + 'er', '\x9d'), ('surface', 'sanitize'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-8', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1'), ('introduc' + 'er', '\x9e'), ('surface', 'sanitize'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-9', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1'), ('introduc' + 'er', '\x9f'), ('surface', 'sanitize'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-10', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1:2'), ('introduc' + 'er', '\x1bP'), ('surface', 'sanitize'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-11', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1:2'), ('introduc' + 'er', '\x1b]'), ('surface', 'sanitize'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-12', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1:2'), ('introduc' + 'er', '\x1bX'), ('surface', 'sanitize'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-13', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1:2'), ('introduc' + 'er', '\x1b^'), ('surface', 'sanitize'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-14', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1:2'), ('introduc' + 'er', '\x1b_'), ('surface', 'sanitize'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-15', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1:2'), ('introduc' + 'er', '\x90'), ('surface', 'sanitize'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-16', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1:2'), ('introduc' + 'er', '\x98'), ('surface', 'sanitize'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-17', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1:2'), ('introduc' + 'er', '\x9d'), ('surface', 'sanitize'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-18', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1:2'), ('introduc' + 'er', '\x9e'), ('surface', 'sanitize'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-19', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1:2'), ('introduc' + 'er', '\x9f'), ('surface', 'sanitize'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-20', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1 $'), ('introduc' + 'er', '\x1bP'), ('surface', 'sanitize'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-21', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1 $'), ('introduc' + 'er', '\x1b]'), ('surface', 'sanitize'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-22', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1 $'), ('introduc' + 'er', '\x1bX'), ('surface', 'sanitize'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-23', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1 $'), ('introduc' + 'er', '\x1b^'), ('surface', 'sanitize'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-24', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1 $'), ('introduc' + 'er', '\x1b_'), ('surface', 'sanitize'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-25', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1 $'), ('introduc' + 'er', '\x90'), ('surface', 'sanitize'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-26', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1 $'), ('introduc' + 'er', '\x98'), ('surface', 'sanitize'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-27', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1 $'), ('introduc' + 'er', '\x9d'), ('surface', 'sanitize'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-28', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1 $'), ('introduc' + 'er', '\x9e'), ('surface', 'sanitize'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-29', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1 $'), ('introduc' + 'er', '\x9f'), ('surface', 'sanitize'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-30', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1'), ('introduc' + 'er', '\x1bP'), ('surface', 'receipt'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-31', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1'), ('introduc' + 'er', '\x1b]'), ('surface', 'receipt'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-32', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1'), ('introduc' + 'er', '\x1bX'), ('surface', 'receipt'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-33', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1'), ('introduc' + 'er', '\x1b^'), ('surface', 'receipt'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-34', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1'), ('introduc' + 'er', '\x1b_'), ('surface', 'receipt'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-35', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1'), ('introduc' + 'er', '\x90'), ('surface', 'receipt'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-36', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1'), ('introduc' + 'er', '\x98'), ('surface', 'receipt'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-37', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1'), ('introduc' + 'er', '\x9d'), ('surface', 'receipt'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-38', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1'), ('introduc' + 'er', '\x9e'), ('surface', 'receipt'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-39', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1'), ('introduc' + 'er', '\x9f'), ('surface', 'receipt'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-40', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1:2'), ('introduc' + 'er', '\x1bP'), ('surface', 'receipt'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-41', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1:2'), ('introduc' + 'er', '\x1b]'), ('surface', 'receipt'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-42', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1:2'), ('introduc' + 'er', '\x1bX'), ('surface', 'receipt'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-43', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1:2'), ('introduc' + 'er', '\x1b^'), ('surface', 'receipt'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-44', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1:2'), ('introduc' + 'er', '\x1b_'), ('surface', 'receipt'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-45', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1:2'), ('introduc' + 'er', '\x90'), ('surface', 'receipt'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-46', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1:2'), ('introduc' + 'er', '\x98'), ('surface', 'receipt'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-47', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1:2'), ('introduc' + 'er', '\x9d'), ('surface', 'receipt'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-48', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1:2'), ('introduc' + 'er', '\x9e'), ('surface', 'receipt'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-49', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1:2'), ('introduc' + 'er', '\x9f'), ('surface', 'receipt'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-50', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1 $'), ('introduc' + 'er', '\x1bP'), ('surface', 'receipt'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-51', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1 $'), ('introduc' + 'er', '\x1b]'), ('surface', 'receipt'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-52', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1 $'), ('introduc' + 'er', '\x1bX'), ('surface', 'receipt'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-53', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1 $'), ('introduc' + 'er', '\x1b^'), ('surface', 'receipt'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-54', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1 $'), ('introduc' + 'er', '\x1b_'), ('surface', 'receipt'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-55', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1 $'), ('introduc' + 'er', '\x90'), ('surface', 'receipt'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-56', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1 $'), ('introduc' + 'er', '\x98'), ('surface', 'receipt'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-57', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1 $'), ('introduc' + 'er', '\x9d'), ('surface', 'receipt'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-58', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1 $'), ('introduc' + 'er', '\x9e'), ('surface', 'receipt'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-59', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1 $'), ('introduc' + 'er', '\x9f'), ('surface', 'receipt'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-60', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1'), ('introduc' + 'er', '\x1bP'), ('surface', 'guidance'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-61', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1'), ('introduc' + 'er', '\x1b]'), ('surface', 'guidance'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-62', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1'), ('introduc' + 'er', '\x1bX'), ('surface', 'guidance'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-63', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1'), ('introduc' + 'er', '\x1b^'), ('surface', 'guidance'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-64', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1'), ('introduc' + 'er', '\x1b_'), ('surface', 'guidance'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-65', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1'), ('introduc' + 'er', '\x90'), ('surface', 'guidance'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-66', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1'), ('introduc' + 'er', '\x98'), ('surface', 'guidance'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-67', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1'), ('introduc' + 'er', '\x9d'), ('surface', 'guidance'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-68', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1'), ('introduc' + 'er', '\x9e'), ('surface', 'guidance'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-69', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1'), ('introduc' + 'er', '\x9f'), ('surface', 'guidance'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-70', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1:2'), ('introduc' + 'er', '\x1bP'), ('surface', 'guidance'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-71', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1:2'), ('introduc' + 'er', '\x1b]'), ('surface', 'guidance'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-72', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1:2'), ('introduc' + 'er', '\x1bX'), ('surface', 'guidance'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-73', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1:2'), ('introduc' + 'er', '\x1b^'), ('surface', 'guidance'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-74', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1:2'), ('introduc' + 'er', '\x1b_'), ('surface', 'guidance'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-75', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1:2'), ('introduc' + 'er', '\x90'), ('surface', 'guidance'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-76', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1:2'), ('introduc' + 'er', '\x98'), ('surface', 'guidance'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-77', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1:2'), ('introduc' + 'er', '\x9d'), ('surface', 'guidance'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-78', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1:2'), ('introduc' + 'er', '\x9e'), ('surface', 'guidance'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-79', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1:2'), ('introduc' + 'er', '\x9f'), ('surface', 'guidance'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-80', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1 $'), ('introduc' + 'er', '\x1bP'), ('surface', 'guidance'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-81', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1 $'), ('introduc' + 'er', '\x1b]'), ('surface', 'guidance'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-82', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1 $'), ('introduc' + 'er', '\x1bX'), ('surface', 'guidance'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-83', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1 $'), ('introduc' + 'er', '\x1b^'), ('surface', 'guidance'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-84', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1 $'), ('introduc' + 'er', '\x1b_'), ('surface', 'guidance'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-85', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1 $'), ('introduc' + 'er', '\x90'), ('surface', 'guidance'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-86', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1 $'), ('introduc' + 'er', '\x98'), ('surface', 'guidance'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-87', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1 $'), ('introduc' + 'er', '\x9d'), ('surface', 'guidance'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-88', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1 $'), ('introduc' + 'er', '\x9e'), ('surface', 'guidance'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-89', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1 $'), ('introduc' + 'er', '\x9f'), ('surface', 'guidance'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-90', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1'), ('introduc' + 'er', '\x1bP'), ('surface', 'proposal'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-91', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1'), ('introduc' + 'er', '\x1b]'), ('surface', 'proposal'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-92', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1'), ('introduc' + 'er', '\x1bX'), ('surface', 'proposal'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-93', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1'), ('introduc' + 'er', '\x1b^'), ('surface', 'proposal'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-94', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1'), ('introduc' + 'er', '\x1b_'), ('surface', 'proposal'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-95', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1'), ('introduc' + 'er', '\x90'), ('surface', 'proposal'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-96', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1'), ('introduc' + 'er', '\x98'), ('surface', 'proposal'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-97', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1'), ('introduc' + 'er', '\x9d'), ('surface', 'proposal'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-98', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1'), ('introduc' + 'er', '\x9e'), ('surface', 'proposal'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-99', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1'), ('introduc' + 'er', '\x9f'), ('surface', 'proposal'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-100', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1:2'), ('introduc' + 'er', '\x1bP'), ('surface', 'proposal'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-101', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1:2'), ('introduc' + 'er', '\x1b]'), ('surface', 'proposal'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-102', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1:2'), ('introduc' + 'er', '\x1bX'), ('surface', 'proposal'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-103', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1:2'), ('introduc' + 'er', '\x1b^'), ('surface', 'proposal'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-104', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1:2'), ('introduc' + 'er', '\x1b_'), ('surface', 'proposal'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-105', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1:2'), ('introduc' + 'er', '\x90'), ('surface', 'proposal'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-106', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1:2'), ('introduc' + 'er', '\x98'), ('surface', 'proposal'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-107', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1:2'), ('introduc' + 'er', '\x9d'), ('surface', 'proposal'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-108', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1:2'), ('introduc' + 'er', '\x9e'), ('surface', 'proposal'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-109', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1:2'), ('introduc' + 'er', '\x9f'), ('surface', 'proposal'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-110', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1 $'), ('introduc' + 'er', '\x1bP'), ('surface', 'proposal'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-111', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1 $'), ('introduc' + 'er', '\x1b]'), ('surface', 'proposal'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-112', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1 $'), ('introduc' + 'er', '\x1bX'), ('surface', 'proposal'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-113', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1 $'), ('introduc' + 'er', '\x1b^'), ('surface', 'proposal'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-114', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1 $'), ('introduc' + 'er', '\x1b_'), ('surface', 'proposal'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-115', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1 $'), ('introduc' + 'er', '\x90'), ('surface', 'proposal'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-116', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1 $'), ('introduc' + 'er', '\x98'), ('surface', 'proposal'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-117', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1 $'), ('introduc' + 'er', '\x9d'), ('surface', 'proposal'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-118', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1 $'), ('introduc' + 'er', '\x9e'), ('surface', 'proposal'))),
    ('nfa-test_display_provenance_covers_every_string_form_and_header-119', 'tests.unit.core.test_primitives.test_display_provenance_covers_every_string_form_and_header', (('header', '1 $'), ('introduc' + 'er', '\x9f'), ('surface', 'proposal'))),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-0', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', (('prefix', '\x1b(0'), ('surface', 'sanitize'))),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-1', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', (('prefix', '\x1b[1:2m'), ('surface', 'sanitize'))),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-2', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', (('prefix', '\x1b[1$m'), ('surface', 'sanitize'))),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-3', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', (('prefix', '\x1bP1'), ('surface', 'sanitize'))),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-4', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', (('prefix', '\x1b]\x1bP1'), ('surface', 'sanitize'))),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-5', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', (('prefix', '\x901'), ('surface', 'sanitize'))),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-6', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', (('prefix', '\x9b1'), ('surface', 'sanitize'))),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-7', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', (('prefix', '\x1b[1:2'), ('surface', 'sanitize'))),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-8', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', (('prefix', '\x1b]1'), ('surface', 'sanitize'))),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-9', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', (('prefix', '\x9d1'), ('surface', 'sanitize'))),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-10', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', (('prefix', '\x1b(0'), ('surface', 'receipt'))),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-11', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', (('prefix', '\x1b[1:2m'), ('surface', 'receipt'))),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-12', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', (('prefix', '\x1b[1$m'), ('surface', 'receipt'))),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-13', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', (('prefix', '\x1bP1'), ('surface', 'receipt'))),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-14', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', (('prefix', '\x1b]\x1bP1'), ('surface', 'receipt'))),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-15', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', (('prefix', '\x901'), ('surface', 'receipt'))),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-16', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', (('prefix', '\x9b1'), ('surface', 'receipt'))),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-17', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', (('prefix', '\x1b[1:2'), ('surface', 'receipt'))),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-18', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', (('prefix', '\x1b]1'), ('surface', 'receipt'))),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-19', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', (('prefix', '\x9d1'), ('surface', 'receipt'))),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-20', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', (('prefix', '\x1b(0'), ('surface', 'guidance'))),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-21', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', (('prefix', '\x1b[1:2m'), ('surface', 'guidance'))),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-22', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', (('prefix', '\x1b[1$m'), ('surface', 'guidance'))),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-23', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', (('prefix', '\x1bP1'), ('surface', 'guidance'))),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-24', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', (('prefix', '\x1b]\x1bP1'), ('surface', 'guidance'))),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-25', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', (('prefix', '\x901'), ('surface', 'guidance'))),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-26', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', (('prefix', '\x9b1'), ('surface', 'guidance'))),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-27', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', (('prefix', '\x1b[1:2'), ('surface', 'guidance'))),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-28', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', (('prefix', '\x1b]1'), ('surface', 'guidance'))),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-29', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', (('prefix', '\x9d1'), ('surface', 'guidance'))),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-30', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', (('prefix', '\x1b(0'), ('surface', 'proposal'))),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-31', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', (('prefix', '\x1b[1:2m'), ('surface', 'proposal'))),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-32', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', (('prefix', '\x1b[1$m'), ('surface', 'proposal'))),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-33', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', (('prefix', '\x1bP1'), ('surface', 'proposal'))),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-34', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', (('prefix', '\x1b]\x1bP1'), ('surface', 'proposal'))),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-35', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', (('prefix', '\x901'), ('surface', 'proposal'))),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-36', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', (('prefix', '\x9b1'), ('surface', 'proposal'))),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-37', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', (('prefix', '\x1b[1:2'), ('surface', 'proposal'))),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-38', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', (('prefix', '\x1b]1'), ('surface', 'proposal'))),
    ('nfa-test_display_provenance_masks_low_entropy_keys_after_every_header-39', 'tests.unit.core.test_primitives.test_display_provenance_masks_low_entropy_keys_after_every_header', (('prefix', '\x9d1'), ('surface', 'proposal'))),
    ('nfa-test_display_provenance_masks_overlaps_inside_an_ordinary_match-0', 'tests.unit.core.test_primitives.test_display_provenance_masks_overlaps_inside_an_ordinary_match', (('family', 'aws'), ('surface', 'sanitize'))),
    ('nfa-test_display_provenance_masks_overlaps_inside_an_ordinary_match-1', 'tests.unit.core.test_primitives.test_display_provenance_masks_overlaps_inside_an_ordinary_match', (('family', 'github'), ('surface', 'sanitize'))),
    ('nfa-test_display_provenance_masks_overlaps_inside_an_ordinary_match-2', 'tests.unit.core.test_primitives.test_display_provenance_masks_overlaps_inside_an_ordinary_match', (('family', 'aws'), ('surface', 'receipt'))),
    ('nfa-test_display_provenance_masks_overlaps_inside_an_ordinary_match-3', 'tests.unit.core.test_primitives.test_display_provenance_masks_overlaps_inside_an_ordinary_match', (('family', 'github'), ('surface', 'receipt'))),
    ('nfa-test_display_provenance_masks_overlaps_inside_an_ordinary_match-4', 'tests.unit.core.test_primitives.test_display_provenance_masks_overlaps_inside_an_ordinary_match', (('family', 'aws'), ('surface', 'guidance'))),
    ('nfa-test_display_provenance_masks_overlaps_inside_an_ordinary_match-5', 'tests.unit.core.test_primitives.test_display_provenance_masks_overlaps_inside_an_ordinary_match', (('family', 'github'), ('surface', 'guidance'))),
    ('nfa-test_display_provenance_masks_overlaps_inside_an_ordinary_match-6', 'tests.unit.core.test_primitives.test_display_provenance_masks_overlaps_inside_an_ordinary_match', (('family', 'aws'), ('surface', 'proposal'))),
    ('nfa-test_display_provenance_masks_overlaps_inside_an_ordinary_match-7', 'tests.unit.core.test_primitives.test_display_provenance_masks_overlaps_inside_an_ordinary_match', (('family', 'github'), ('surface', 'proposal'))),
    ('nfa-test_display_provenance_overlaps_and_headers_are_independent_in_threads-0', 'tests.unit.core.test_primitives.test_display_provenance_overlaps_and_headers_are_independent_in_threads', (('surface', 'sanitize'),)),
    ('nfa-test_display_provenance_overlaps_and_headers_are_independent_in_threads-1', 'tests.unit.core.test_primitives.test_display_provenance_overlaps_and_headers_are_independent_in_threads', (('surface', 'receipt'),)),
    ('nfa-test_display_provenance_overlaps_and_headers_are_independent_in_threads-2', 'tests.unit.core.test_primitives.test_display_provenance_overlaps_and_headers_are_independent_in_threads', (('surface', 'guidance'),)),
    ('nfa-test_display_provenance_overlaps_and_headers_are_independent_in_threads-3', 'tests.unit.core.test_primitives.test_display_provenance_overlaps_and_headers_are_independent_in_threads', (('surface', 'proposal'),)),
    ('nfa-test_display_reassembled_tokens_use_markers_before_caller_redaction-0', 'tests.unit.core.test_primitives.test_display_reassembled_tokens_use_markers_before_caller_redaction', (('family', 'aws'), ('prefix', ''), ('removed', '\x1b[31m'))),
    ('nfa-test_display_reassembled_tokens_use_markers_before_caller_redaction-1', 'tests.unit.core.test_primitives.test_display_reassembled_tokens_use_markers_before_caller_redaction', (('family', 'github'), ('prefix', ''), ('removed', '\x1b[31m'))),
    ('nfa-test_display_reassembled_tokens_use_markers_before_caller_redaction-2', 'tests.unit.core.test_primitives.test_display_reassembled_tokens_use_markers_before_caller_redaction', (('family', 'aws'), ('prefix', ''), ('removed', '\r'))),
    ('nfa-test_display_reassembled_tokens_use_markers_before_caller_redaction-3', 'tests.unit.core.test_primitives.test_display_reassembled_tokens_use_markers_before_caller_redaction', (('family', 'github'), ('prefix', ''), ('removed', '\r'))),
    ('nfa-test_display_reassembled_tokens_use_markers_before_caller_redaction-4', 'tests.unit.core.test_primitives.test_display_reassembled_tokens_use_markers_before_caller_redaction', (('family', 'aws'), ('prefix', ''), ('removed', '\x00'))),
    ('nfa-test_display_reassembled_tokens_use_markers_before_caller_redaction-5', 'tests.unit.core.test_primitives.test_display_reassembled_tokens_use_markers_before_caller_redaction', (('family', 'github'), ('prefix', ''), ('removed', '\x00'))),
    ('nfa-test_display_reassembled_tokens_use_markers_before_caller_redaction-6', 'tests.unit.core.test_primitives.test_display_reassembled_tokens_use_markers_before_caller_redaction', (('family', 'aws'), ('prefix', '\x1b[31m'), ('removed', '\x1b[31m'))),
    ('nfa-test_display_reassembled_tokens_use_markers_before_caller_redaction-7', 'tests.unit.core.test_primitives.test_display_reassembled_tokens_use_markers_before_caller_redaction', (('family', 'github'), ('prefix', '\x1b[31m'), ('removed', '\x1b[31m'))),
    ('nfa-test_display_reassembled_tokens_use_markers_before_caller_redaction-8', 'tests.unit.core.test_primitives.test_display_reassembled_tokens_use_markers_before_caller_redaction', (('family', 'aws'), ('prefix', '\x1b[31m'), ('removed', '\r'))),
    ('nfa-test_display_reassembled_tokens_use_markers_before_caller_redaction-9', 'tests.unit.core.test_primitives.test_display_reassembled_tokens_use_markers_before_caller_redaction', (('family', 'github'), ('prefix', '\x1b[31m'), ('removed', '\r'))),
    ('nfa-test_display_reassembled_tokens_use_markers_before_caller_redaction-10', 'tests.unit.core.test_primitives.test_display_reassembled_tokens_use_markers_before_caller_redaction', (('family', 'aws'), ('prefix', '\x1b[31m'), ('removed', '\x00'))),
    ('nfa-test_display_reassembled_tokens_use_markers_before_caller_redaction-11', 'tests.unit.core.test_primitives.test_display_reassembled_tokens_use_markers_before_caller_redaction', (('family', 'github'), ('prefix', '\x1b[31m'), ('removed', '\x00'))),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-0', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 0),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-1', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 1),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-2', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 2),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-3', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 3),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-4', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 4),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-5', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 5),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-6', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 6),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-7', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 7),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-8', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 8),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-9', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 9),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-10', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 10),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-11', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 11),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-12', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 12),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-13', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 13),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-14', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 14),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-15', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 15),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-16', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 16),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-17', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 17),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-18', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 18),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-19', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 19),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-20', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 20),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-21', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 21),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-22', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 22),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-23', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 23),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-24', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 24),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-25', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 25),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-26', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 26),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-27', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 28),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-28', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 29),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-29', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 30),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-30', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 31),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-31', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 127),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-32', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 128),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-33', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 129),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-34', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 130),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-35', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 131),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-36', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 132),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-37', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 133),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-38', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 134),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-39', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 135),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-40', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 136),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-41', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 137),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-42', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 138),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-43', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 139),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-44', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 140),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-45', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 141),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-46', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 142),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-47', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 143),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-48', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 144),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-49', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 145),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-50', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 146),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-51', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 147),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-52', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 148),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-53', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 149),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-54', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 150),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-55', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 151),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-56', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 152),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-57', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 153),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-58', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 154),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-59', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 155),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-60', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 156),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-61', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 157),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-62', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 158),)),
    ('nfa-test_display_removed_controls_preserve_secret_boundaries-63', 'tests.unit.core.test_primitives.test_display_removed_controls_preserve_secret_boundaries', (('code', 159),)),
    ('nfa-test_display_rendered_segments_keep_visible_credential_whitespace-0', 'tests.unit.core.test_primitives.test_display_rendered_segments_keep_visible_credential_whitespace', (('control', '\t'), ('prefix', '\x1b['), ('surface', 'sanitize'))),
    ('nfa-test_display_rendered_segments_keep_visible_credential_whitespace-1', 'tests.unit.core.test_primitives.test_display_rendered_segments_keep_visible_credential_whitespace', (('control', '\t'), ('prefix', '\x1b[1'), ('surface', 'sanitize'))),
    ('nfa-test_display_rendered_segments_keep_visible_credential_whitespace-2', 'tests.unit.core.test_primitives.test_display_rendered_segments_keep_visible_credential_whitespace', (('control', '\n'), ('prefix', '\x1b['), ('surface', 'sanitize'))),
    ('nfa-test_display_rendered_segments_keep_visible_credential_whitespace-3', 'tests.unit.core.test_primitives.test_display_rendered_segments_keep_visible_credential_whitespace', (('control', '\n'), ('prefix', '\x1b[1'), ('surface', 'sanitize'))),
    ('nfa-test_display_rendered_segments_keep_visible_credential_whitespace-4', 'tests.unit.core.test_primitives.test_display_rendered_segments_keep_visible_credential_whitespace', (('control', '\t'), ('prefix', '\x1b['), ('surface', 'receipt'))),
    ('nfa-test_display_rendered_segments_keep_visible_credential_whitespace-5', 'tests.unit.core.test_primitives.test_display_rendered_segments_keep_visible_credential_whitespace', (('control', '\t'), ('prefix', '\x1b[1'), ('surface', 'receipt'))),
    ('nfa-test_display_rendered_segments_keep_visible_credential_whitespace-6', 'tests.unit.core.test_primitives.test_display_rendered_segments_keep_visible_credential_whitespace', (('control', '\n'), ('prefix', '\x1b['), ('surface', 'receipt'))),
    ('nfa-test_display_rendered_segments_keep_visible_credential_whitespace-7', 'tests.unit.core.test_primitives.test_display_rendered_segments_keep_visible_credential_whitespace', (('control', '\n'), ('prefix', '\x1b[1'), ('surface', 'receipt'))),
    ('nfa-test_display_rendered_segments_keep_visible_credential_whitespace-8', 'tests.unit.core.test_primitives.test_display_rendered_segments_keep_visible_credential_whitespace', (('control', '\t'), ('prefix', '\x1b['), ('surface', 'guidance'))),
    ('nfa-test_display_rendered_segments_keep_visible_credential_whitespace-9', 'tests.unit.core.test_primitives.test_display_rendered_segments_keep_visible_credential_whitespace', (('control', '\t'), ('prefix', '\x1b[1'), ('surface', 'guidance'))),
    ('nfa-test_display_rendered_segments_keep_visible_credential_whitespace-10', 'tests.unit.core.test_primitives.test_display_rendered_segments_keep_visible_credential_whitespace', (('control', '\n'), ('prefix', '\x1b['), ('surface', 'guidance'))),
    ('nfa-test_display_rendered_segments_keep_visible_credential_whitespace-11', 'tests.unit.core.test_primitives.test_display_rendered_segments_keep_visible_credential_whitespace', (('control', '\n'), ('prefix', '\x1b[1'), ('surface', 'guidance'))),
    ('nfa-test_display_rendered_segments_keep_visible_credential_whitespace-12', 'tests.unit.core.test_primitives.test_display_rendered_segments_keep_visible_credential_whitespace', (('control', '\t'), ('prefix', '\x1b['), ('surface', 'proposal'))),
    ('nfa-test_display_rendered_segments_keep_visible_credential_whitespace-13', 'tests.unit.core.test_primitives.test_display_rendered_segments_keep_visible_credential_whitespace', (('control', '\t'), ('prefix', '\x1b[1'), ('surface', 'proposal'))),
    ('nfa-test_display_rendered_segments_keep_visible_credential_whitespace-14', 'tests.unit.core.test_primitives.test_display_rendered_segments_keep_visible_credential_whitespace', (('control', '\n'), ('prefix', '\x1b['), ('surface', 'proposal'))),
    ('nfa-test_display_rendered_segments_keep_visible_credential_whitespace-15', 'tests.unit.core.test_primitives.test_display_rendered_segments_keep_visible_credential_whitespace', (('control', '\n'), ('prefix', '\x1b[1'), ('surface', 'proposal'))),
    ('nfa-test_display_rendered_segments_preserve_visible_space_inside_nonsecret-0', 'tests.unit.core.test_primitives.test_display_rendered_segments_preserve_visible_space_inside_nonsecret', (('control', '\t'), ('surface', 'sanitize'))),
    ('nfa-test_display_rendered_segments_preserve_visible_space_inside_nonsecret-1', 'tests.unit.core.test_primitives.test_display_rendered_segments_preserve_visible_space_inside_nonsecret', (('control', '\n'), ('surface', 'sanitize'))),
    ('nfa-test_display_rendered_segments_preserve_visible_space_inside_nonsecret-2', 'tests.unit.core.test_primitives.test_display_rendered_segments_preserve_visible_space_inside_nonsecret', (('control', '\t'), ('surface', 'receipt'))),
    ('nfa-test_display_rendered_segments_preserve_visible_space_inside_nonsecret-3', 'tests.unit.core.test_primitives.test_display_rendered_segments_preserve_visible_space_inside_nonsecret', (('control', '\n'), ('surface', 'receipt'))),
    ('nfa-test_display_rendered_segments_preserve_visible_space_inside_nonsecret-4', 'tests.unit.core.test_primitives.test_display_rendered_segments_preserve_visible_space_inside_nonsecret', (('control', '\t'), ('surface', 'guidance'))),
    ('nfa-test_display_rendered_segments_preserve_visible_space_inside_nonsecret-5', 'tests.unit.core.test_primitives.test_display_rendered_segments_preserve_visible_space_inside_nonsecret', (('control', '\n'), ('surface', 'guidance'))),
    ('nfa-test_display_rendered_segments_preserve_visible_space_inside_nonsecret-6', 'tests.unit.core.test_primitives.test_display_rendered_segments_preserve_visible_space_inside_nonsecret', (('control', '\t'), ('surface', 'proposal'))),
    ('nfa-test_display_rendered_segments_preserve_visible_space_inside_nonsecret-7', 'tests.unit.core.test_primitives.test_display_rendered_segments_preserve_visible_space_inside_nonsecret', (('control', '\n'), ('surface', 'proposal'))),
    ('nfa-test_display_rendered_segments_seal_hidden_token_prefix-0', 'tests.unit.core.test_primitives.test_display_rendered_segments_seal_hidden_token_prefix', (('introduc' + 'er', '\x1b]'), ('surface', 'sanitize'), ('terminat' + 'or', '\x07'))),
    ('nfa-test_display_rendered_segments_seal_hidden_token_prefix-1', 'tests.unit.core.test_primitives.test_display_rendered_segments_seal_hidden_token_prefix', (('introduc' + 'er', '\x1bP'), ('surface', 'sanitize'), ('terminat' + 'or', '\x07'))),
    ('nfa-test_display_rendered_segments_seal_hidden_token_prefix-2', 'tests.unit.core.test_primitives.test_display_rendered_segments_seal_hidden_token_prefix', (('introduc' + 'er', '\x1b]'), ('surface', 'sanitize'), ('terminat' + 'or', '\x1b\\'))),
    ('nfa-test_display_rendered_segments_seal_hidden_token_prefix-3', 'tests.unit.core.test_primitives.test_display_rendered_segments_seal_hidden_token_prefix', (('introduc' + 'er', '\x1bP'), ('surface', 'sanitize'), ('terminat' + 'or', '\x1b\\'))),
    ('nfa-test_display_rendered_segments_seal_hidden_token_prefix-4', 'tests.unit.core.test_primitives.test_display_rendered_segments_seal_hidden_token_prefix', (('introduc' + 'er', '\x1b]'), ('surface', 'receipt'), ('terminat' + 'or', '\x07'))),
    ('nfa-test_display_rendered_segments_seal_hidden_token_prefix-5', 'tests.unit.core.test_primitives.test_display_rendered_segments_seal_hidden_token_prefix', (('introduc' + 'er', '\x1bP'), ('surface', 'receipt'), ('terminat' + 'or', '\x07'))),
    ('nfa-test_display_rendered_segments_seal_hidden_token_prefix-6', 'tests.unit.core.test_primitives.test_display_rendered_segments_seal_hidden_token_prefix', (('introduc' + 'er', '\x1b]'), ('surface', 'receipt'), ('terminat' + 'or', '\x1b\\'))),
    ('nfa-test_display_rendered_segments_seal_hidden_token_prefix-7', 'tests.unit.core.test_primitives.test_display_rendered_segments_seal_hidden_token_prefix', (('introduc' + 'er', '\x1bP'), ('surface', 'receipt'), ('terminat' + 'or', '\x1b\\'))),
    ('nfa-test_display_rendered_segments_seal_hidden_token_prefix-8', 'tests.unit.core.test_primitives.test_display_rendered_segments_seal_hidden_token_prefix', (('introduc' + 'er', '\x1b]'), ('surface', 'guidance'), ('terminat' + 'or', '\x07'))),
    ('nfa-test_display_rendered_segments_seal_hidden_token_prefix-9', 'tests.unit.core.test_primitives.test_display_rendered_segments_seal_hidden_token_prefix', (('introduc' + 'er', '\x1bP'), ('surface', 'guidance'), ('terminat' + 'or', '\x07'))),
    ('nfa-test_display_rendered_segments_seal_hidden_token_prefix-10', 'tests.unit.core.test_primitives.test_display_rendered_segments_seal_hidden_token_prefix', (('introduc' + 'er', '\x1b]'), ('surface', 'guidance'), ('terminat' + 'or', '\x1b\\'))),
    ('nfa-test_display_rendered_segments_seal_hidden_token_prefix-11', 'tests.unit.core.test_primitives.test_display_rendered_segments_seal_hidden_token_prefix', (('introduc' + 'er', '\x1bP'), ('surface', 'guidance'), ('terminat' + 'or', '\x1b\\'))),
    ('nfa-test_display_rendered_segments_seal_hidden_token_prefix-12', 'tests.unit.core.test_primitives.test_display_rendered_segments_seal_hidden_token_prefix', (('introduc' + 'er', '\x1b]'), ('surface', 'proposal'), ('terminat' + 'or', '\x07'))),
    ('nfa-test_display_rendered_segments_seal_hidden_token_prefix-13', 'tests.unit.core.test_primitives.test_display_rendered_segments_seal_hidden_token_prefix', (('introduc' + 'er', '\x1bP'), ('surface', 'proposal'), ('terminat' + 'or', '\x07'))),
    ('nfa-test_display_rendered_segments_seal_hidden_token_prefix-14', 'tests.unit.core.test_primitives.test_display_rendered_segments_seal_hidden_token_prefix', (('introduc' + 'er', '\x1b]'), ('surface', 'proposal'), ('terminat' + 'or', '\x1b\\'))),
    ('nfa-test_display_rendered_segments_seal_hidden_token_prefix-15', 'tests.unit.core.test_primitives.test_display_rendered_segments_seal_hidden_token_prefix', (('introduc' + 'er', '\x1bP'), ('surface', 'proposal'), ('terminat' + 'or', '\x1b\\'))),
    ('nfa-test_display_rendered_segments_still_join_fully_removed_controls-0', 'tests.unit.core.test_primitives.test_display_rendered_segments_still_join_fully_removed_controls', (('control', '\x00'), ('surface', 'sanitize'))),
    ('nfa-test_display_rendered_segments_still_join_fully_removed_controls-1', 'tests.unit.core.test_primitives.test_display_rendered_segments_still_join_fully_removed_controls', (('control', '\r'), ('surface', 'sanitize'))),
    ('nfa-test_display_rendered_segments_still_join_fully_removed_controls-2', 'tests.unit.core.test_primitives.test_display_rendered_segments_still_join_fully_removed_controls', (('control', '\x7f'), ('surface', 'sanitize'))),
    ('nfa-test_display_rendered_segments_still_join_fully_removed_controls-3', 'tests.unit.core.test_primitives.test_display_rendered_segments_still_join_fully_removed_controls', (('control', '\x85'), ('surface', 'sanitize'))),
    ('nfa-test_display_rendered_segments_still_join_fully_removed_controls-4', 'tests.unit.core.test_primitives.test_display_rendered_segments_still_join_fully_removed_controls', (('control', '\x00'), ('surface', 'receipt'))),
    ('nfa-test_display_rendered_segments_still_join_fully_removed_controls-5', 'tests.unit.core.test_primitives.test_display_rendered_segments_still_join_fully_removed_controls', (('control', '\r'), ('surface', 'receipt'))),
    ('nfa-test_display_rendered_segments_still_join_fully_removed_controls-6', 'tests.unit.core.test_primitives.test_display_rendered_segments_still_join_fully_removed_controls', (('control', '\x7f'), ('surface', 'receipt'))),
    ('nfa-test_display_rendered_segments_still_join_fully_removed_controls-7', 'tests.unit.core.test_primitives.test_display_rendered_segments_still_join_fully_removed_controls', (('control', '\x85'), ('surface', 'receipt'))),
    ('nfa-test_display_rendered_segments_still_join_fully_removed_controls-8', 'tests.unit.core.test_primitives.test_display_rendered_segments_still_join_fully_removed_controls', (('control', '\x00'), ('surface', 'guidance'))),
    ('nfa-test_display_rendered_segments_still_join_fully_removed_controls-9', 'tests.unit.core.test_primitives.test_display_rendered_segments_still_join_fully_removed_controls', (('control', '\r'), ('surface', 'guidance'))),
    ('nfa-test_display_rendered_segments_still_join_fully_removed_controls-10', 'tests.unit.core.test_primitives.test_display_rendered_segments_still_join_fully_removed_controls', (('control', '\x7f'), ('surface', 'guidance'))),
    ('nfa-test_display_rendered_segments_still_join_fully_removed_controls-11', 'tests.unit.core.test_primitives.test_display_rendered_segments_still_join_fully_removed_controls', (('control', '\x85'), ('surface', 'guidance'))),
    ('nfa-test_display_rendered_segments_still_join_fully_removed_controls-12', 'tests.unit.core.test_primitives.test_display_rendered_segments_still_join_fully_removed_controls', (('control', '\x00'), ('surface', 'proposal'))),
    ('nfa-test_display_rendered_segments_still_join_fully_removed_controls-13', 'tests.unit.core.test_primitives.test_display_rendered_segments_still_join_fully_removed_controls', (('control', '\r'), ('surface', 'proposal'))),
    ('nfa-test_display_rendered_segments_still_join_fully_removed_controls-14', 'tests.unit.core.test_primitives.test_display_rendered_segments_still_join_fully_removed_controls', (('control', '\x7f'), ('surface', 'proposal'))),
    ('nfa-test_display_rendered_segments_still_join_fully_removed_controls-15', 'tests.unit.core.test_primitives.test_display_rendered_segments_still_join_fully_removed_controls', (('control', '\x85'), ('surface', 'proposal'))),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-0', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', (('control', '\x07'), ('header', '\x1b['), ('surface', 'sanitize'))),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-1', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', (('control', '\t'), ('header', '\x1b['), ('surface', 'sanitize'))),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-2', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', (('control', '\n'), ('header', '\x1b['), ('surface', 'sanitize'))),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-3', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', (('control', '\x07'), ('header', '\x9b'), ('surface', 'sanitize'))),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-4', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', (('control', '\t'), ('header', '\x9b'), ('surface', 'sanitize'))),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-5', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', (('control', '\n'), ('header', '\x9b'), ('surface', 'sanitize'))),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-6', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', (('control', '\x07'), ('header', '\x1b('), ('surface', 'sanitize'))),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-7', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', (('control', '\t'), ('header', '\x1b('), ('surface', 'sanitize'))),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-8', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', (('control', '\n'), ('header', '\x1b('), ('surface', 'sanitize'))),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-9', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', (('control', '\x07'), ('header', '\x1b['), ('surface', 'receipt'))),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-10', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', (('control', '\t'), ('header', '\x1b['), ('surface', 'receipt'))),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-11', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', (('control', '\n'), ('header', '\x1b['), ('surface', 'receipt'))),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-12', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', (('control', '\x07'), ('header', '\x9b'), ('surface', 'receipt'))),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-13', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', (('control', '\t'), ('header', '\x9b'), ('surface', 'receipt'))),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-14', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', (('control', '\n'), ('header', '\x9b'), ('surface', 'receipt'))),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-15', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', (('control', '\x07'), ('header', '\x1b('), ('surface', 'receipt'))),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-16', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', (('control', '\t'), ('header', '\x1b('), ('surface', 'receipt'))),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-17', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', (('control', '\n'), ('header', '\x1b('), ('surface', 'receipt'))),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-18', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', (('control', '\x07'), ('header', '\x1b['), ('surface', 'guidance'))),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-19', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', (('control', '\t'), ('header', '\x1b['), ('surface', 'guidance'))),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-20', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', (('control', '\n'), ('header', '\x1b['), ('surface', 'guidance'))),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-21', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', (('control', '\x07'), ('header', '\x9b'), ('surface', 'guidance'))),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-22', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', (('control', '\t'), ('header', '\x9b'), ('surface', 'guidance'))),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-23', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', (('control', '\n'), ('header', '\x9b'), ('surface', 'guidance'))),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-24', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', (('control', '\x07'), ('header', '\x1b('), ('surface', 'guidance'))),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-25', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', (('control', '\t'), ('header', '\x1b('), ('surface', 'guidance'))),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-26', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', (('control', '\n'), ('header', '\x1b('), ('surface', 'guidance'))),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-27', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', (('control', '\x07'), ('header', '\x1b['), ('surface', 'proposal'))),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-28', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', (('control', '\t'), ('header', '\x1b['), ('surface', 'proposal'))),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-29', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', (('control', '\n'), ('header', '\x1b['), ('surface', 'proposal'))),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-30', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', (('control', '\x07'), ('header', '\x9b'), ('surface', 'proposal'))),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-31', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', (('control', '\t'), ('header', '\x9b'), ('surface', 'proposal'))),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-32', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', (('control', '\n'), ('header', '\x9b'), ('surface', 'proposal'))),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-33', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', (('control', '\x07'), ('header', '\x1b('), ('surface', 'proposal'))),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-34', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', (('control', '\t'), ('header', '\x1b('), ('surface', 'proposal'))),
    ('nfa-test_display_renderer_provenance_keeps_control_interrupted_headers-35', 'tests.unit.core.test_primitives.test_display_renderer_provenance_keeps_control_interrupted_headers', (('control', '\n'), ('header', '\x1b('), ('surface', 'proposal'))),
    ('nfa-test_display_renderer_provenance_recovers_consumed_credential_label-0', 'tests.unit.core.test_primitives.test_display_renderer_provenance_recovers_consumed_credential_label', (('surface', 'sanitize'),)),
    ('nfa-test_display_renderer_provenance_recovers_consumed_credential_label-1', 'tests.unit.core.test_primitives.test_display_renderer_provenance_recovers_consumed_credential_label', (('surface', 'receipt'),)),
    ('nfa-test_display_renderer_provenance_recovers_consumed_credential_label-2', 'tests.unit.core.test_primitives.test_display_renderer_provenance_recovers_consumed_credential_label', (('surface', 'guidance'),)),
    ('nfa-test_display_renderer_provenance_recovers_consumed_credential_label-3', 'tests.unit.core.test_primitives.test_display_renderer_provenance_recovers_consumed_credential_label', (('surface', 'proposal'),)),
    ('nfa-test_display_restored_union_masks_before_boundary_changes_or_clipping-0', 'tests.unit.core.test_primitives.test_display_restored_union_masks_before_boundary_changes_or_clipping', (('case', 'changed-' + 'boundary'), ('surface', 'sanitize'))),
    ('nfa-test_display_restored_union_masks_before_boundary_changes_or_clipping-1', 'tests.unit.core.test_primitives.test_display_restored_union_masks_before_boundary_changes_or_clipping', (('case', 'changed-' + 'boundary'), ('surface', 'receipt'))),
    ('nfa-test_display_restored_union_masks_before_boundary_changes_or_clipping-2', 'tests.unit.core.test_primitives.test_display_restored_union_masks_before_boundary_changes_or_clipping', (('case', 'changed-' + 'boundary'), ('surface', 'guidance'))),
    ('nfa-test_display_restored_union_masks_before_boundary_changes_or_clipping-3', 'tests.unit.core.test_primitives.test_display_restored_union_masks_before_boundary_changes_or_clipping', (('case', 'changed-' + 'boundary'), ('surface', 'proposal'))),
    ('nfa-test_display_restored_union_masks_before_boundary_changes_or_clipping-4', 'tests.unit.core.test_primitives.test_display_restored_union_masks_before_boundary_changes_or_clipping', (('case', 'ordered-' + 'coverage'), ('surface', 'sanitize'))),
    ('nfa-test_display_restored_union_masks_before_boundary_changes_or_clipping-5', 'tests.unit.core.test_primitives.test_display_restored_union_masks_before_boundary_changes_or_clipping', (('case', 'ordered-' + 'coverage'), ('surface', 'receipt'))),
    ('nfa-test_display_restored_union_masks_before_boundary_changes_or_clipping-6', 'tests.unit.core.test_primitives.test_display_restored_union_masks_before_boundary_changes_or_clipping', (('case', 'ordered-' + 'coverage'), ('surface', 'guidance'))),
    ('nfa-test_display_restored_union_masks_before_boundary_changes_or_clipping-7', 'tests.unit.core.test_primitives.test_display_restored_union_masks_before_boundary_changes_or_clipping', (('case', 'ordered-' + 'coverage'), ('surface', 'proposal'))),
    ('nfa-test_display_restored_union_masks_before_boundary_changes_or_clipping-8', 'tests.unit.core.test_primitives.test_display_restored_union_masks_before_boundary_changes_or_clipping', (('case', 'finite-c' + 'lip'), ('surface', 'sanitize'))),
    ('nfa-test_display_restored_union_masks_before_boundary_changes_or_clipping-9', 'tests.unit.core.test_primitives.test_display_restored_union_masks_before_boundary_changes_or_clipping', (('case', 'finite-c' + 'lip'), ('surface', 'receipt'))),
    ('nfa-test_display_restored_union_masks_before_boundary_changes_or_clipping-10', 'tests.unit.core.test_primitives.test_display_restored_union_masks_before_boundary_changes_or_clipping', (('case', 'finite-c' + 'lip'), ('surface', 'guidance'))),
    ('nfa-test_display_restored_union_masks_before_boundary_changes_or_clipping-11', 'tests.unit.core.test_primitives.test_display_restored_union_masks_before_boundary_changes_or_clipping', (('case', 'finite-c' + 'lip'), ('surface', 'proposal'))),
    ('nfa-test_display_source_guard_cannot_complete_a_new_credential_or_tear_a_mask-0', 'tests.unit.core.test_primitives.test_display_source_guard_cannot_complete_a_new_credential_or_tear_a_mask', (('surface', 'sanitize'),)),
    ('nfa-test_display_source_guard_cannot_complete_a_new_credential_or_tear_a_mask-1', 'tests.unit.core.test_primitives.test_display_source_guard_cannot_complete_a_new_credential_or_tear_a_mask', (('surface', 'receipt'),)),
    ('nfa-test_display_source_guard_cannot_complete_a_new_credential_or_tear_a_mask-2', 'tests.unit.core.test_primitives.test_display_source_guard_cannot_complete_a_new_credential_or_tear_a_mask', (('surface', 'guidance'),)),
    ('nfa-test_display_source_guard_cannot_complete_a_new_credential_or_tear_a_mask-3', 'tests.unit.core.test_primitives.test_display_source_guard_cannot_complete_a_new_credential_or_tear_a_mask', (('surface', 'proposal'),)),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-0', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', (('control', '\x00'), ('head', 'Bearer'), ('surface', 'sanitize'), ('tail', 'anything' + '_sixteen' + '_chars'))),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-1', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', (('control', '\r'), ('head', 'Bearer'), ('surface', 'sanitize'), ('tail', 'anything' + '_sixteen' + '_chars'))),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-2', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', (('control', '\x7f'), ('head', 'Bearer'), ('surface', 'sanitize'), ('tail', 'anything' + '_sixteen' + '_chars'))),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-3', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', (('control', '\x85'), ('head', 'Bearer'), ('surface', 'sanitize'), ('tail', 'anything' + '_sixteen' + '_chars'))),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-4', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', (('control', '\x00'), ('head', 'password'), ('surface', 'sanitize'), ('tail', 'is abcde' + 'fgh'))),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-5', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', (('control', '\r'), ('head', 'password'), ('surface', 'sanitize'), ('tail', 'is abcde' + 'fgh'))),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-6', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', (('control', '\x7f'), ('head', 'password'), ('surface', 'sanitize'), ('tail', 'is abcde' + 'fgh'))),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-7', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', (('control', '\x85'), ('head', 'password'), ('surface', 'sanitize'), ('tail', 'is abcde' + 'fgh'))),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-8', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', (('control', '\x00'), ('head', 'Bearer'), ('surface', 'receipt'), ('tail', 'anything' + '_sixteen' + '_chars'))),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-9', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', (('control', '\r'), ('head', 'Bearer'), ('surface', 'receipt'), ('tail', 'anything' + '_sixteen' + '_chars'))),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-10', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', (('control', '\x7f'), ('head', 'Bearer'), ('surface', 'receipt'), ('tail', 'anything' + '_sixteen' + '_chars'))),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-11', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', (('control', '\x85'), ('head', 'Bearer'), ('surface', 'receipt'), ('tail', 'anything' + '_sixteen' + '_chars'))),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-12', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', (('control', '\x00'), ('head', 'password'), ('surface', 'receipt'), ('tail', 'is abcde' + 'fgh'))),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-13', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', (('control', '\r'), ('head', 'password'), ('surface', 'receipt'), ('tail', 'is abcde' + 'fgh'))),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-14', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', (('control', '\x7f'), ('head', 'password'), ('surface', 'receipt'), ('tail', 'is abcde' + 'fgh'))),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-15', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', (('control', '\x85'), ('head', 'password'), ('surface', 'receipt'), ('tail', 'is abcde' + 'fgh'))),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-16', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', (('control', '\x00'), ('head', 'Bearer'), ('surface', 'guidance'), ('tail', 'anything' + '_sixteen' + '_chars'))),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-17', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', (('control', '\r'), ('head', 'Bearer'), ('surface', 'guidance'), ('tail', 'anything' + '_sixteen' + '_chars'))),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-18', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', (('control', '\x7f'), ('head', 'Bearer'), ('surface', 'guidance'), ('tail', 'anything' + '_sixteen' + '_chars'))),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-19', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', (('control', '\x85'), ('head', 'Bearer'), ('surface', 'guidance'), ('tail', 'anything' + '_sixteen' + '_chars'))),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-20', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', (('control', '\x00'), ('head', 'password'), ('surface', 'guidance'), ('tail', 'is abcde' + 'fgh'))),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-21', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', (('control', '\r'), ('head', 'password'), ('surface', 'guidance'), ('tail', 'is abcde' + 'fgh'))),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-22', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', (('control', '\x7f'), ('head', 'password'), ('surface', 'guidance'), ('tail', 'is abcde' + 'fgh'))),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-23', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', (('control', '\x85'), ('head', 'password'), ('surface', 'guidance'), ('tail', 'is abcde' + 'fgh'))),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-24', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', (('control', '\x00'), ('head', 'Bearer'), ('surface', 'proposal'), ('tail', 'anything' + '_sixteen' + '_chars'))),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-25', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', (('control', '\r'), ('head', 'Bearer'), ('surface', 'proposal'), ('tail', 'anything' + '_sixteen' + '_chars'))),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-26', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', (('control', '\x7f'), ('head', 'Bearer'), ('surface', 'proposal'), ('tail', 'anything' + '_sixteen' + '_chars'))),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-27', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', (('control', '\x85'), ('head', 'Bearer'), ('surface', 'proposal'), ('tail', 'anything' + '_sixteen' + '_chars'))),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-28', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', (('control', '\x00'), ('head', 'password'), ('surface', 'proposal'), ('tail', 'is abcde' + 'fgh'))),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-29', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', (('control', '\r'), ('head', 'password'), ('surface', 'proposal'), ('tail', 'is abcde' + 'fgh'))),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-30', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', (('control', '\x7f'), ('head', 'password'), ('surface', 'proposal'), ('tail', 'is abcde' + 'fgh'))),
    ('nfa-test_display_source_segments_do_not_invent_credential_whitespace-31', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_invent_credential_whitespace', (('control', '\x85'), ('head', 'password'), ('surface', 'proposal'), ('tail', 'is abcde' + 'fgh'))),
    ('nfa-test_display_source_segments_do_not_join_visible_context_through_hidden_payload-0', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_join_visible_context_through_hidden_payload', (('introduc' + 'er', '\x1b]'), ('surface', 'sanitize'), ('terminat' + 'or', '\x07'))),
    ('nfa-test_display_source_segments_do_not_join_visible_context_through_hidden_payload-1', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_join_visible_context_through_hidden_payload', (('introduc' + 'er', '\x1bP'), ('surface', 'sanitize'), ('terminat' + 'or', '\x07'))),
    ('nfa-test_display_source_segments_do_not_join_visible_context_through_hidden_payload-2', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_join_visible_context_through_hidden_payload', (('introduc' + 'er', '\x1b]'), ('surface', 'sanitize'), ('terminat' + 'or', '\x1b\\'))),
    ('nfa-test_display_source_segments_do_not_join_visible_context_through_hidden_payload-3', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_join_visible_context_through_hidden_payload', (('introduc' + 'er', '\x1bP'), ('surface', 'sanitize'), ('terminat' + 'or', '\x1b\\'))),
    ('nfa-test_display_source_segments_do_not_join_visible_context_through_hidden_payload-4', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_join_visible_context_through_hidden_payload', (('introduc' + 'er', '\x1b]'), ('surface', 'receipt'), ('terminat' + 'or', '\x07'))),
    ('nfa-test_display_source_segments_do_not_join_visible_context_through_hidden_payload-5', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_join_visible_context_through_hidden_payload', (('introduc' + 'er', '\x1bP'), ('surface', 'receipt'), ('terminat' + 'or', '\x07'))),
    ('nfa-test_display_source_segments_do_not_join_visible_context_through_hidden_payload-6', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_join_visible_context_through_hidden_payload', (('introduc' + 'er', '\x1b]'), ('surface', 'receipt'), ('terminat' + 'or', '\x1b\\'))),
    ('nfa-test_display_source_segments_do_not_join_visible_context_through_hidden_payload-7', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_join_visible_context_through_hidden_payload', (('introduc' + 'er', '\x1bP'), ('surface', 'receipt'), ('terminat' + 'or', '\x1b\\'))),
    ('nfa-test_display_source_segments_do_not_join_visible_context_through_hidden_payload-8', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_join_visible_context_through_hidden_payload', (('introduc' + 'er', '\x1b]'), ('surface', 'guidance'), ('terminat' + 'or', '\x07'))),
    ('nfa-test_display_source_segments_do_not_join_visible_context_through_hidden_payload-9', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_join_visible_context_through_hidden_payload', (('introduc' + 'er', '\x1bP'), ('surface', 'guidance'), ('terminat' + 'or', '\x07'))),
    ('nfa-test_display_source_segments_do_not_join_visible_context_through_hidden_payload-10', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_join_visible_context_through_hidden_payload', (('introduc' + 'er', '\x1b]'), ('surface', 'guidance'), ('terminat' + 'or', '\x1b\\'))),
    ('nfa-test_display_source_segments_do_not_join_visible_context_through_hidden_payload-11', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_join_visible_context_through_hidden_payload', (('introduc' + 'er', '\x1bP'), ('surface', 'guidance'), ('terminat' + 'or', '\x1b\\'))),
    ('nfa-test_display_source_segments_do_not_join_visible_context_through_hidden_payload-12', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_join_visible_context_through_hidden_payload', (('introduc' + 'er', '\x1b]'), ('surface', 'proposal'), ('terminat' + 'or', '\x07'))),
    ('nfa-test_display_source_segments_do_not_join_visible_context_through_hidden_payload-13', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_join_visible_context_through_hidden_payload', (('introduc' + 'er', '\x1bP'), ('surface', 'proposal'), ('terminat' + 'or', '\x07'))),
    ('nfa-test_display_source_segments_do_not_join_visible_context_through_hidden_payload-14', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_join_visible_context_through_hidden_payload', (('introduc' + 'er', '\x1b]'), ('surface', 'proposal'), ('terminat' + 'or', '\x1b\\'))),
    ('nfa-test_display_source_segments_do_not_join_visible_context_through_hidden_payload-15', 'tests.unit.core.test_primitives.test_display_source_segments_do_not_join_visible_context_through_hidden_payload', (('introduc' + 'er', '\x1bP'), ('surface', 'proposal'), ('terminat' + 'or', '\x1b\\'))),
    ('nfa-test_display_source_segments_keep_prefixed_secret_context_detectable-0', 'tests.unit.core.test_primitives.test_display_source_segments_keep_prefixed_secret_context_detectable', (('surface', 'sanitize'), ('value', 'service_' + 'password' + '_name=te' + 'st-value' + '-123456'))),
    ('nfa-test_display_source_segments_keep_prefixed_secret_context_detectable-1', 'tests.unit.core.test_primitives.test_display_source_segments_keep_prefixed_secret_context_detectable', (('surface', 'sanitize'), ('value', 'https://' + 'user:tes' + 't-value-' + '123456@e' + 'xample.t' + 'est'))),
    ('nfa-test_display_source_segments_keep_prefixed_secret_context_detectable-2', 'tests.unit.core.test_primitives.test_display_source_segments_keep_prefixed_secret_context_detectable', (('surface', 'sanitize'), ('value', '://user:' + 'test-val' + 'ue-12345' + '6@exampl' + 'e.test'))),
    ('nfa-test_display_source_segments_keep_prefixed_secret_context_detectable-3', 'tests.unit.core.test_primitives.test_display_source_segments_keep_prefixed_secret_context_detectable', (('surface', 'receipt'), ('value', 'service_' + 'password' + '_name=te' + 'st-value' + '-123456'))),
    ('nfa-test_display_source_segments_keep_prefixed_secret_context_detectable-4', 'tests.unit.core.test_primitives.test_display_source_segments_keep_prefixed_secret_context_detectable', (('surface', 'receipt'), ('value', 'https://' + 'user:tes' + 't-value-' + '123456@e' + 'xample.t' + 'est'))),
    ('nfa-test_display_source_segments_keep_prefixed_secret_context_detectable-5', 'tests.unit.core.test_primitives.test_display_source_segments_keep_prefixed_secret_context_detectable', (('surface', 'receipt'), ('value', '://user:' + 'test-val' + 'ue-12345' + '6@exampl' + 'e.test'))),
    ('nfa-test_display_source_segments_keep_prefixed_secret_context_detectable-6', 'tests.unit.core.test_primitives.test_display_source_segments_keep_prefixed_secret_context_detectable', (('surface', 'guidance'), ('value', 'service_' + 'password' + '_name=te' + 'st-value' + '-123456'))),
    ('nfa-test_display_source_segments_keep_prefixed_secret_context_detectable-7', 'tests.unit.core.test_primitives.test_display_source_segments_keep_prefixed_secret_context_detectable', (('surface', 'guidance'), ('value', 'https://' + 'user:tes' + 't-value-' + '123456@e' + 'xample.t' + 'est'))),
    ('nfa-test_display_source_segments_keep_prefixed_secret_context_detectable-8', 'tests.unit.core.test_primitives.test_display_source_segments_keep_prefixed_secret_context_detectable', (('surface', 'guidance'), ('value', '://user:' + 'test-val' + 'ue-12345' + '6@exampl' + 'e.test'))),
    ('nfa-test_display_source_segments_keep_prefixed_secret_context_detectable-9', 'tests.unit.core.test_primitives.test_display_source_segments_keep_prefixed_secret_context_detectable', (('surface', 'proposal'), ('value', 'service_' + 'password' + '_name=te' + 'st-value' + '-123456'))),
    ('nfa-test_display_source_segments_keep_prefixed_secret_context_detectable-10', 'tests.unit.core.test_primitives.test_display_source_segments_keep_prefixed_secret_context_detectable', (('surface', 'proposal'), ('value', 'https://' + 'user:tes' + 't-value-' + '123456@e' + 'xample.t' + 'est'))),
    ('nfa-test_display_source_segments_keep_prefixed_secret_context_detectable-11', 'tests.unit.core.test_primitives.test_display_source_segments_keep_prefixed_secret_context_detectable', (('surface', 'proposal'), ('value', '://user:' + 'test-val' + 'ue-12345' + '6@exampl' + 'e.test'))),
    ('nfa-test_display_source_segments_seal_suppressed_strings-0', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', (('hidden', 'token='), ('introduc' + 'er', '\x1b]'), ('surface', 'sanitize'), ('tail', 'after'), ('terminat' + 'or', '\x07'))),
    ('nfa-test_display_source_segments_seal_suppressed_strings-1', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', (('hidden', 'token='), ('introduc' + 'er', '\x1bP'), ('surface', 'sanitize'), ('tail', 'after'), ('terminat' + 'or', '\x07'))),
    ('nfa-test_display_source_segments_seal_suppressed_strings-2', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', (('hidden', 'token='), ('introduc' + 'er', '\x1b]'), ('surface', 'sanitize'), ('tail', 'after'), ('terminat' + 'or', '\x1b\\'))),
    ('nfa-test_display_source_segments_seal_suppressed_strings-3', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', (('hidden', 'token='), ('introduc' + 'er', '\x1bP'), ('surface', 'sanitize'), ('tail', 'after'), ('terminat' + 'or', '\x1b\\'))),
    ('nfa-test_display_source_segments_seal_suppressed_strings-4', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', (('hidden', 'Bearer'), ('introduc' + 'er', '\x1b]'), ('surface', 'sanitize'), ('tail', 'after_si' + 'xteen_ch' + 'ars'), ('terminat' + 'or', '\x07'))),
    ('nfa-test_display_source_segments_seal_suppressed_strings-5', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', (('hidden', 'Bearer'), ('introduc' + 'er', '\x1bP'), ('surface', 'sanitize'), ('tail', 'after_si' + 'xteen_ch' + 'ars'), ('terminat' + 'or', '\x07'))),
    ('nfa-test_display_source_segments_seal_suppressed_strings-6', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', (('hidden', 'Bearer'), ('introduc' + 'er', '\x1b]'), ('surface', 'sanitize'), ('tail', 'after_si' + 'xteen_ch' + 'ars'), ('terminat' + 'or', '\x1b\\'))),
    ('nfa-test_display_source_segments_seal_suppressed_strings-7', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', (('hidden', 'Bearer'), ('introduc' + 'er', '\x1bP'), ('surface', 'sanitize'), ('tail', 'after_si' + 'xteen_ch' + 'ars'), ('terminat' + 'or', '\x1b\\'))),
    ('nfa-test_display_source_segments_seal_suppressed_strings-8', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', (('hidden', '-----BEG' + 'IN PRIVA' + 'TE KEY--' + '---'), ('introduc' + 'er', '\x1b]'), ('surface', 'sanitize'), ('tail', 'after'), ('terminat' + 'or', '\x07'))),
    ('nfa-test_display_source_segments_seal_suppressed_strings-9', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', (('hidden', '-----BEG' + 'IN PRIVA' + 'TE KEY--' + '---'), ('introduc' + 'er', '\x1bP'), ('surface', 'sanitize'), ('tail', 'after'), ('terminat' + 'or', '\x07'))),
    ('nfa-test_display_source_segments_seal_suppressed_strings-10', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', (('hidden', '-----BEG' + 'IN PRIVA' + 'TE KEY--' + '---'), ('introduc' + 'er', '\x1b]'), ('surface', 'sanitize'), ('tail', 'after'), ('terminat' + 'or', '\x1b\\'))),
    ('nfa-test_display_source_segments_seal_suppressed_strings-11', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', (('hidden', '-----BEG' + 'IN PRIVA' + 'TE KEY--' + '---'), ('introduc' + 'er', '\x1bP'), ('surface', 'sanitize'), ('tail', 'after'), ('terminat' + 'or', '\x1b\\'))),
    ('nfa-test_display_source_segments_seal_suppressed_strings-12', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', (('hidden', 'token='), ('introduc' + 'er', '\x1b]'), ('surface', 'receipt'), ('tail', 'after'), ('terminat' + 'or', '\x07'))),
    ('nfa-test_display_source_segments_seal_suppressed_strings-13', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', (('hidden', 'token='), ('introduc' + 'er', '\x1bP'), ('surface', 'receipt'), ('tail', 'after'), ('terminat' + 'or', '\x07'))),
    ('nfa-test_display_source_segments_seal_suppressed_strings-14', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', (('hidden', 'token='), ('introduc' + 'er', '\x1b]'), ('surface', 'receipt'), ('tail', 'after'), ('terminat' + 'or', '\x1b\\'))),
    ('nfa-test_display_source_segments_seal_suppressed_strings-15', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', (('hidden', 'token='), ('introduc' + 'er', '\x1bP'), ('surface', 'receipt'), ('tail', 'after'), ('terminat' + 'or', '\x1b\\'))),
    ('nfa-test_display_source_segments_seal_suppressed_strings-16', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', (('hidden', 'Bearer'), ('introduc' + 'er', '\x1b]'), ('surface', 'receipt'), ('tail', 'after_si' + 'xteen_ch' + 'ars'), ('terminat' + 'or', '\x07'))),
    ('nfa-test_display_source_segments_seal_suppressed_strings-17', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', (('hidden', 'Bearer'), ('introduc' + 'er', '\x1bP'), ('surface', 'receipt'), ('tail', 'after_si' + 'xteen_ch' + 'ars'), ('terminat' + 'or', '\x07'))),
    ('nfa-test_display_source_segments_seal_suppressed_strings-18', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', (('hidden', 'Bearer'), ('introduc' + 'er', '\x1b]'), ('surface', 'receipt'), ('tail', 'after_si' + 'xteen_ch' + 'ars'), ('terminat' + 'or', '\x1b\\'))),
    ('nfa-test_display_source_segments_seal_suppressed_strings-19', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', (('hidden', 'Bearer'), ('introduc' + 'er', '\x1bP'), ('surface', 'receipt'), ('tail', 'after_si' + 'xteen_ch' + 'ars'), ('terminat' + 'or', '\x1b\\'))),
    ('nfa-test_display_source_segments_seal_suppressed_strings-20', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', (('hidden', '-----BEG' + 'IN PRIVA' + 'TE KEY--' + '---'), ('introduc' + 'er', '\x1b]'), ('surface', 'receipt'), ('tail', 'after'), ('terminat' + 'or', '\x07'))),
    ('nfa-test_display_source_segments_seal_suppressed_strings-21', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', (('hidden', '-----BEG' + 'IN PRIVA' + 'TE KEY--' + '---'), ('introduc' + 'er', '\x1bP'), ('surface', 'receipt'), ('tail', 'after'), ('terminat' + 'or', '\x07'))),
    ('nfa-test_display_source_segments_seal_suppressed_strings-22', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', (('hidden', '-----BEG' + 'IN PRIVA' + 'TE KEY--' + '---'), ('introduc' + 'er', '\x1b]'), ('surface', 'receipt'), ('tail', 'after'), ('terminat' + 'or', '\x1b\\'))),
    ('nfa-test_display_source_segments_seal_suppressed_strings-23', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', (('hidden', '-----BEG' + 'IN PRIVA' + 'TE KEY--' + '---'), ('introduc' + 'er', '\x1bP'), ('surface', 'receipt'), ('tail', 'after'), ('terminat' + 'or', '\x1b\\'))),
    ('nfa-test_display_source_segments_seal_suppressed_strings-24', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', (('hidden', 'token='), ('introduc' + 'er', '\x1b]'), ('surface', 'guidance'), ('tail', 'after'), ('terminat' + 'or', '\x07'))),
    ('nfa-test_display_source_segments_seal_suppressed_strings-25', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', (('hidden', 'token='), ('introduc' + 'er', '\x1bP'), ('surface', 'guidance'), ('tail', 'after'), ('terminat' + 'or', '\x07'))),
    ('nfa-test_display_source_segments_seal_suppressed_strings-26', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', (('hidden', 'token='), ('introduc' + 'er', '\x1b]'), ('surface', 'guidance'), ('tail', 'after'), ('terminat' + 'or', '\x1b\\'))),
    ('nfa-test_display_source_segments_seal_suppressed_strings-27', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', (('hidden', 'token='), ('introduc' + 'er', '\x1bP'), ('surface', 'guidance'), ('tail', 'after'), ('terminat' + 'or', '\x1b\\'))),
    ('nfa-test_display_source_segments_seal_suppressed_strings-28', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', (('hidden', 'Bearer'), ('introduc' + 'er', '\x1b]'), ('surface', 'guidance'), ('tail', 'after_si' + 'xteen_ch' + 'ars'), ('terminat' + 'or', '\x07'))),
    ('nfa-test_display_source_segments_seal_suppressed_strings-29', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', (('hidden', 'Bearer'), ('introduc' + 'er', '\x1bP'), ('surface', 'guidance'), ('tail', 'after_si' + 'xteen_ch' + 'ars'), ('terminat' + 'or', '\x07'))),
    ('nfa-test_display_source_segments_seal_suppressed_strings-30', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', (('hidden', 'Bearer'), ('introduc' + 'er', '\x1b]'), ('surface', 'guidance'), ('tail', 'after_si' + 'xteen_ch' + 'ars'), ('terminat' + 'or', '\x1b\\'))),
    ('nfa-test_display_source_segments_seal_suppressed_strings-31', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', (('hidden', 'Bearer'), ('introduc' + 'er', '\x1bP'), ('surface', 'guidance'), ('tail', 'after_si' + 'xteen_ch' + 'ars'), ('terminat' + 'or', '\x1b\\'))),
    ('nfa-test_display_source_segments_seal_suppressed_strings-32', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', (('hidden', '-----BEG' + 'IN PRIVA' + 'TE KEY--' + '---'), ('introduc' + 'er', '\x1b]'), ('surface', 'guidance'), ('tail', 'after'), ('terminat' + 'or', '\x07'))),
    ('nfa-test_display_source_segments_seal_suppressed_strings-33', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', (('hidden', '-----BEG' + 'IN PRIVA' + 'TE KEY--' + '---'), ('introduc' + 'er', '\x1bP'), ('surface', 'guidance'), ('tail', 'after'), ('terminat' + 'or', '\x07'))),
    ('nfa-test_display_source_segments_seal_suppressed_strings-34', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', (('hidden', '-----BEG' + 'IN PRIVA' + 'TE KEY--' + '---'), ('introduc' + 'er', '\x1b]'), ('surface', 'guidance'), ('tail', 'after'), ('terminat' + 'or', '\x1b\\'))),
    ('nfa-test_display_source_segments_seal_suppressed_strings-35', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', (('hidden', '-----BEG' + 'IN PRIVA' + 'TE KEY--' + '---'), ('introduc' + 'er', '\x1bP'), ('surface', 'guidance'), ('tail', 'after'), ('terminat' + 'or', '\x1b\\'))),
    ('nfa-test_display_source_segments_seal_suppressed_strings-36', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', (('hidden', 'token='), ('introduc' + 'er', '\x1b]'), ('surface', 'proposal'), ('tail', 'after'), ('terminat' + 'or', '\x07'))),
    ('nfa-test_display_source_segments_seal_suppressed_strings-37', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', (('hidden', 'token='), ('introduc' + 'er', '\x1bP'), ('surface', 'proposal'), ('tail', 'after'), ('terminat' + 'or', '\x07'))),
    ('nfa-test_display_source_segments_seal_suppressed_strings-38', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', (('hidden', 'token='), ('introduc' + 'er', '\x1b]'), ('surface', 'proposal'), ('tail', 'after'), ('terminat' + 'or', '\x1b\\'))),
    ('nfa-test_display_source_segments_seal_suppressed_strings-39', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', (('hidden', 'token='), ('introduc' + 'er', '\x1bP'), ('surface', 'proposal'), ('tail', 'after'), ('terminat' + 'or', '\x1b\\'))),
    ('nfa-test_display_source_segments_seal_suppressed_strings-40', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', (('hidden', 'Bearer'), ('introduc' + 'er', '\x1b]'), ('surface', 'proposal'), ('tail', 'after_si' + 'xteen_ch' + 'ars'), ('terminat' + 'or', '\x07'))),
    ('nfa-test_display_source_segments_seal_suppressed_strings-41', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', (('hidden', 'Bearer'), ('introduc' + 'er', '\x1bP'), ('surface', 'proposal'), ('tail', 'after_si' + 'xteen_ch' + 'ars'), ('terminat' + 'or', '\x07'))),
    ('nfa-test_display_source_segments_seal_suppressed_strings-42', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', (('hidden', 'Bearer'), ('introduc' + 'er', '\x1b]'), ('surface', 'proposal'), ('tail', 'after_si' + 'xteen_ch' + 'ars'), ('terminat' + 'or', '\x1b\\'))),
    ('nfa-test_display_source_segments_seal_suppressed_strings-43', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', (('hidden', 'Bearer'), ('introduc' + 'er', '\x1bP'), ('surface', 'proposal'), ('tail', 'after_si' + 'xteen_ch' + 'ars'), ('terminat' + 'or', '\x1b\\'))),
    ('nfa-test_display_source_segments_seal_suppressed_strings-44', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', (('hidden', '-----BEG' + 'IN PRIVA' + 'TE KEY--' + '---'), ('introduc' + 'er', '\x1b]'), ('surface', 'proposal'), ('tail', 'after'), ('terminat' + 'or', '\x07'))),
    ('nfa-test_display_source_segments_seal_suppressed_strings-45', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', (('hidden', '-----BEG' + 'IN PRIVA' + 'TE KEY--' + '---'), ('introduc' + 'er', '\x1bP'), ('surface', 'proposal'), ('tail', 'after'), ('terminat' + 'or', '\x07'))),
    ('nfa-test_display_source_segments_seal_suppressed_strings-46', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', (('hidden', '-----BEG' + 'IN PRIVA' + 'TE KEY--' + '---'), ('introduc' + 'er', '\x1b]'), ('surface', 'proposal'), ('tail', 'after'), ('terminat' + 'or', '\x1b\\'))),
    ('nfa-test_display_source_segments_seal_suppressed_strings-47', 'tests.unit.core.test_primitives.test_display_source_segments_seal_suppressed_strings', (('hidden', '-----BEG' + 'IN PRIVA' + 'TE KEY--' + '---'), ('introduc' + 'er', '\x1bP'), ('surface', 'proposal'), ('tail', 'after'), ('terminat' + 'or', '\x1b\\'))),
    ('nfa-test_display_source_segments_still_mask_visible_secrets_on_both_sides-0', 'tests.unit.core.test_primitives.test_display_source_segments_still_mask_visible_secrets_on_both_sides', (('introduc' + 'er', '\x1b]'), ('surface', 'sanitize'), ('terminat' + 'or', '\x07'))),
    ('nfa-test_display_source_segments_still_mask_visible_secrets_on_both_sides-1', 'tests.unit.core.test_primitives.test_display_source_segments_still_mask_visible_secrets_on_both_sides', (('introduc' + 'er', '\x1bP'), ('surface', 'sanitize'), ('terminat' + 'or', '\x07'))),
    ('nfa-test_display_source_segments_still_mask_visible_secrets_on_both_sides-2', 'tests.unit.core.test_primitives.test_display_source_segments_still_mask_visible_secrets_on_both_sides', (('introduc' + 'er', '\x1b]'), ('surface', 'sanitize'), ('terminat' + 'or', '\x1b\\'))),
    ('nfa-test_display_source_segments_still_mask_visible_secrets_on_both_sides-3', 'tests.unit.core.test_primitives.test_display_source_segments_still_mask_visible_secrets_on_both_sides', (('introduc' + 'er', '\x1bP'), ('surface', 'sanitize'), ('terminat' + 'or', '\x1b\\'))),
    ('nfa-test_display_source_segments_still_mask_visible_secrets_on_both_sides-4', 'tests.unit.core.test_primitives.test_display_source_segments_still_mask_visible_secrets_on_both_sides', (('introduc' + 'er', '\x1b]'), ('surface', 'receipt'), ('terminat' + 'or', '\x07'))),
    ('nfa-test_display_source_segments_still_mask_visible_secrets_on_both_sides-5', 'tests.unit.core.test_primitives.test_display_source_segments_still_mask_visible_secrets_on_both_sides', (('introduc' + 'er', '\x1bP'), ('surface', 'receipt'), ('terminat' + 'or', '\x07'))),
    ('nfa-test_display_source_segments_still_mask_visible_secrets_on_both_sides-6', 'tests.unit.core.test_primitives.test_display_source_segments_still_mask_visible_secrets_on_both_sides', (('introduc' + 'er', '\x1b]'), ('surface', 'receipt'), ('terminat' + 'or', '\x1b\\'))),
    ('nfa-test_display_source_segments_still_mask_visible_secrets_on_both_sides-7', 'tests.unit.core.test_primitives.test_display_source_segments_still_mask_visible_secrets_on_both_sides', (('introduc' + 'er', '\x1bP'), ('surface', 'receipt'), ('terminat' + 'or', '\x1b\\'))),
    ('nfa-test_display_source_segments_still_mask_visible_secrets_on_both_sides-8', 'tests.unit.core.test_primitives.test_display_source_segments_still_mask_visible_secrets_on_both_sides', (('introduc' + 'er', '\x1b]'), ('surface', 'guidance'), ('terminat' + 'or', '\x07'))),
    ('nfa-test_display_source_segments_still_mask_visible_secrets_on_both_sides-9', 'tests.unit.core.test_primitives.test_display_source_segments_still_mask_visible_secrets_on_both_sides', (('introduc' + 'er', '\x1bP'), ('surface', 'guidance'), ('terminat' + 'or', '\x07'))),
    ('nfa-test_display_source_segments_still_mask_visible_secrets_on_both_sides-10', 'tests.unit.core.test_primitives.test_display_source_segments_still_mask_visible_secrets_on_both_sides', (('introduc' + 'er', '\x1b]'), ('surface', 'guidance'), ('terminat' + 'or', '\x1b\\'))),
    ('nfa-test_display_source_segments_still_mask_visible_secrets_on_both_sides-11', 'tests.unit.core.test_primitives.test_display_source_segments_still_mask_visible_secrets_on_both_sides', (('introduc' + 'er', '\x1bP'), ('surface', 'guidance'), ('terminat' + 'or', '\x1b\\'))),
    ('nfa-test_display_source_segments_still_mask_visible_secrets_on_both_sides-12', 'tests.unit.core.test_primitives.test_display_source_segments_still_mask_visible_secrets_on_both_sides', (('introduc' + 'er', '\x1b]'), ('surface', 'proposal'), ('terminat' + 'or', '\x07'))),
    ('nfa-test_display_source_segments_still_mask_visible_secrets_on_both_sides-13', 'tests.unit.core.test_primitives.test_display_source_segments_still_mask_visible_secrets_on_both_sides', (('introduc' + 'er', '\x1bP'), ('surface', 'proposal'), ('terminat' + 'or', '\x07'))),
    ('nfa-test_display_source_segments_still_mask_visible_secrets_on_both_sides-14', 'tests.unit.core.test_primitives.test_display_source_segments_still_mask_visible_secrets_on_both_sides', (('introduc' + 'er', '\x1b]'), ('surface', 'proposal'), ('terminat' + 'or', '\x1b\\'))),
    ('nfa-test_display_source_segments_still_mask_visible_secrets_on_both_sides-15', 'tests.unit.core.test_primitives.test_display_source_segments_still_mask_visible_secrets_on_both_sides', (('introduc' + 'er', '\x1bP'), ('surface', 'proposal'), ('terminat' + 'or', '\x1b\\'))),
    ('nfa-test_display_source_view_accepts_control_only_nonsecret_text-0', 'tests.unit.core.test_primitives.test_display_source_view_accepts_control_only_nonsecret_text', (('expected', ' '), ('value', '\n'))),
    ('nfa-test_display_source_view_accepts_control_only_nonsecret_text-1', 'tests.unit.core.test_primitives.test_display_source_view_accepts_control_only_nonsecret_text', (('expected', ' '), ('value', '\t\r\x00'))),
    ('nfa-test_display_source_view_accepts_control_only_nonsecret_text-2', 'tests.unit.core.test_primitives.test_display_source_view_accepts_control_only_nonsecret_text', (('expected', ''), ('value', '\r\x00'))),
    ('nfa-test_display_source_view_bounds_repeated_unterminated_pem_work-0', 'tests.unit.core.test_primitives.test_display_source_view_bounds_repeated_unterminated_pem_work', ()),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-0', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x00'), ('prefix', '\x1bP1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-1', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x00'), ('prefix', '\x1b]1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-2', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x00'), ('prefix', '\x1bX1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-3', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x00'), ('prefix', '\x1b^1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-4', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x00'), ('prefix', '\x1b_1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-5', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x00'), ('prefix', '\x901\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-6', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x00'), ('prefix', '\x9d1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-7', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x00'), ('prefix', '\x981\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-8', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x00'), ('prefix', '\x9e1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-9', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x00'), ('prefix', '\x9f1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-10', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x00'), ('prefix', '\x1b(\x000'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-11', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x00'), ('prefix', '\x1b[1:\x002m'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-12', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x00'), ('prefix', '\x9b1:\x002m'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-13', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x00'), ('prefix', '\x1b[1\x002m'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-14', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x00'), ('prefix', '\x1bP1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-15', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x00'), ('prefix', '\x1b]1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-16', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x00'), ('prefix', '\x1bX1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-17', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x00'), ('prefix', '\x1b^1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-18', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x00'), ('prefix', '\x1b_1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-19', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x00'), ('prefix', '\x901\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-20', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x00'), ('prefix', '\x9d1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-21', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x00'), ('prefix', '\x981\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-22', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x00'), ('prefix', '\x9e1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-23', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x00'), ('prefix', '\x9f1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-24', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x00'), ('prefix', '\x1b(\x000'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-25', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x00'), ('prefix', '\x1b[1:\x002m'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-26', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x00'), ('prefix', '\x9b1:\x002m'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-27', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x00'), ('prefix', '\x1b[1\x002m'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-28', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x00'), ('prefix', '\x1bP1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-29', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x00'), ('prefix', '\x1b]1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-30', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x00'), ('prefix', '\x1bX1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-31', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x00'), ('prefix', '\x1b^1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-32', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x00'), ('prefix', '\x1b_1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-33', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x00'), ('prefix', '\x901\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-34', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x00'), ('prefix', '\x9d1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-35', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x00'), ('prefix', '\x981\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-36', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x00'), ('prefix', '\x9e1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-37', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x00'), ('prefix', '\x9f1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-38', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x00'), ('prefix', '\x1b(\x000'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-39', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x00'), ('prefix', '\x1b[1:\x002m'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-40', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x00'), ('prefix', '\x9b1:\x002m'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-41', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x00'), ('prefix', '\x1b[1\x002m'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-42', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x00'), ('prefix', '\x1bP1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-43', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x00'), ('prefix', '\x1b]1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-44', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x00'), ('prefix', '\x1bX1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-45', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x00'), ('prefix', '\x1b^1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-46', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x00'), ('prefix', '\x1b_1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-47', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x00'), ('prefix', '\x901\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-48', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x00'), ('prefix', '\x9d1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-49', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x00'), ('prefix', '\x981\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-50', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x00'), ('prefix', '\x9e1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-51', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x00'), ('prefix', '\x9f1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-52', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x00'), ('prefix', '\x1b(\x000'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-53', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x00'), ('prefix', '\x1b[1:\x002m'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-54', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x00'), ('prefix', '\x9b1:\x002m'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-55', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x00'), ('prefix', '\x1b[1\x002m'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-56', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x08'), ('prefix', '\x1bP1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-57', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x08'), ('prefix', '\x1b]1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-58', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x08'), ('prefix', '\x1bX1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-59', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x08'), ('prefix', '\x1b^1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-60', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x08'), ('prefix', '\x1b_1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-61', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x08'), ('prefix', '\x901\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-62', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x08'), ('prefix', '\x9d1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-63', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x08'), ('prefix', '\x981\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-64', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x08'), ('prefix', '\x9e1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-65', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x08'), ('prefix', '\x9f1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-66', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x08'), ('prefix', '\x1b(\x000'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-67', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x08'), ('prefix', '\x1b[1:\x002m'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-68', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x08'), ('prefix', '\x9b1:\x002m'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-69', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x08'), ('prefix', '\x1b[1\x002m'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-70', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x08'), ('prefix', '\x1bP1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-71', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x08'), ('prefix', '\x1b]1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-72', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x08'), ('prefix', '\x1bX1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-73', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x08'), ('prefix', '\x1b^1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-74', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x08'), ('prefix', '\x1b_1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-75', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x08'), ('prefix', '\x901\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-76', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x08'), ('prefix', '\x9d1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-77', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x08'), ('prefix', '\x981\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-78', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x08'), ('prefix', '\x9e1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-79', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x08'), ('prefix', '\x9f1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-80', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x08'), ('prefix', '\x1b(\x000'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-81', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x08'), ('prefix', '\x1b[1:\x002m'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-82', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x08'), ('prefix', '\x9b1:\x002m'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-83', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x08'), ('prefix', '\x1b[1\x002m'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-84', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x08'), ('prefix', '\x1bP1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-85', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x08'), ('prefix', '\x1b]1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-86', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x08'), ('prefix', '\x1bX1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-87', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x08'), ('prefix', '\x1b^1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-88', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x08'), ('prefix', '\x1b_1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-89', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x08'), ('prefix', '\x901\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-90', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x08'), ('prefix', '\x9d1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-91', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x08'), ('prefix', '\x981\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-92', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x08'), ('prefix', '\x9e1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-93', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x08'), ('prefix', '\x9f1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-94', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x08'), ('prefix', '\x1b(\x000'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-95', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x08'), ('prefix', '\x1b[1:\x002m'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-96', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x08'), ('prefix', '\x9b1:\x002m'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-97', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x08'), ('prefix', '\x1b[1\x002m'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-98', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x08'), ('prefix', '\x1bP1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-99', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x08'), ('prefix', '\x1b]1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-100', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x08'), ('prefix', '\x1bX1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-101', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x08'), ('prefix', '\x1b^1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-102', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x08'), ('prefix', '\x1b_1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-103', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x08'), ('prefix', '\x901\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-104', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x08'), ('prefix', '\x9d1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-105', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x08'), ('prefix', '\x981\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-106', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x08'), ('prefix', '\x9e1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-107', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x08'), ('prefix', '\x9f1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-108', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x08'), ('prefix', '\x1b(\x000'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-109', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x08'), ('prefix', '\x1b[1:\x002m'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-110', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x08'), ('prefix', '\x9b1:\x002m'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-111', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x08'), ('prefix', '\x1b[1\x002m'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-112', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x0b'), ('prefix', '\x1bP1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-113', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x0b'), ('prefix', '\x1b]1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-114', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x0b'), ('prefix', '\x1bX1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-115', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x0b'), ('prefix', '\x1b^1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-116', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x0b'), ('prefix', '\x1b_1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-117', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x0b'), ('prefix', '\x901\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-118', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x0b'), ('prefix', '\x9d1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-119', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x0b'), ('prefix', '\x981\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-120', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x0b'), ('prefix', '\x9e1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-121', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x0b'), ('prefix', '\x9f1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-122', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x0b'), ('prefix', '\x1b(\x000'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-123', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x0b'), ('prefix', '\x1b[1:\x002m'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-124', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x0b'), ('prefix', '\x9b1:\x002m'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-125', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x0b'), ('prefix', '\x1b[1\x002m'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-126', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x0b'), ('prefix', '\x1bP1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-127', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x0b'), ('prefix', '\x1b]1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-128', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x0b'), ('prefix', '\x1bX1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-129', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x0b'), ('prefix', '\x1b^1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-130', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x0b'), ('prefix', '\x1b_1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-131', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x0b'), ('prefix', '\x901\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-132', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x0b'), ('prefix', '\x9d1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-133', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x0b'), ('prefix', '\x981\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-134', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x0b'), ('prefix', '\x9e1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-135', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x0b'), ('prefix', '\x9f1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-136', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x0b'), ('prefix', '\x1b(\x000'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-137', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x0b'), ('prefix', '\x1b[1:\x002m'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-138', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x0b'), ('prefix', '\x9b1:\x002m'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-139', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x0b'), ('prefix', '\x1b[1\x002m'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-140', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x0b'), ('prefix', '\x1bP1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-141', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x0b'), ('prefix', '\x1b]1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-142', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x0b'), ('prefix', '\x1bX1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-143', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x0b'), ('prefix', '\x1b^1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-144', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x0b'), ('prefix', '\x1b_1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-145', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x0b'), ('prefix', '\x901\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-146', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x0b'), ('prefix', '\x9d1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-147', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x0b'), ('prefix', '\x981\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-148', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x0b'), ('prefix', '\x9e1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-149', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x0b'), ('prefix', '\x9f1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-150', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x0b'), ('prefix', '\x1b(\x000'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-151', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x0b'), ('prefix', '\x1b[1:\x002m'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-152', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x0b'), ('prefix', '\x9b1:\x002m'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-153', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x0b'), ('prefix', '\x1b[1\x002m'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-154', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x0b'), ('prefix', '\x1bP1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-155', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x0b'), ('prefix', '\x1b]1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-156', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x0b'), ('prefix', '\x1bX1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-157', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x0b'), ('prefix', '\x1b^1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-158', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x0b'), ('prefix', '\x1b_1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-159', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x0b'), ('prefix', '\x901\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-160', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x0b'), ('prefix', '\x9d1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-161', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x0b'), ('prefix', '\x981\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-162', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x0b'), ('prefix', '\x9e1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-163', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x0b'), ('prefix', '\x9f1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-164', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x0b'), ('prefix', '\x1b(\x000'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-165', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x0b'), ('prefix', '\x1b[1:\x002m'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-166', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x0b'), ('prefix', '\x9b1:\x002m'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-167', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x0b'), ('prefix', '\x1b[1\x002m'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-168', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\r'), ('prefix', '\x1bP1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-169', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\r'), ('prefix', '\x1b]1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-170', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\r'), ('prefix', '\x1bX1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-171', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\r'), ('prefix', '\x1b^1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-172', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\r'), ('prefix', '\x1b_1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-173', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\r'), ('prefix', '\x901\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-174', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\r'), ('prefix', '\x9d1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-175', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\r'), ('prefix', '\x981\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-176', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\r'), ('prefix', '\x9e1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-177', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\r'), ('prefix', '\x9f1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-178', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\r'), ('prefix', '\x1b(\x000'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-179', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\r'), ('prefix', '\x1b[1:\x002m'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-180', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\r'), ('prefix', '\x9b1:\x002m'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-181', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\r'), ('prefix', '\x1b[1\x002m'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-182', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\r'), ('prefix', '\x1bP1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-183', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\r'), ('prefix', '\x1b]1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-184', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\r'), ('prefix', '\x1bX1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-185', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\r'), ('prefix', '\x1b^1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-186', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\r'), ('prefix', '\x1b_1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-187', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\r'), ('prefix', '\x901\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-188', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\r'), ('prefix', '\x9d1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-189', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\r'), ('prefix', '\x981\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-190', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\r'), ('prefix', '\x9e1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-191', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\r'), ('prefix', '\x9f1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-192', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\r'), ('prefix', '\x1b(\x000'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-193', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\r'), ('prefix', '\x1b[1:\x002m'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-194', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\r'), ('prefix', '\x9b1:\x002m'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-195', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\r'), ('prefix', '\x1b[1\x002m'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-196', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\r'), ('prefix', '\x1bP1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-197', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\r'), ('prefix', '\x1b]1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-198', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\r'), ('prefix', '\x1bX1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-199', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\r'), ('prefix', '\x1b^1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-200', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\r'), ('prefix', '\x1b_1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-201', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\r'), ('prefix', '\x901\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-202', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\r'), ('prefix', '\x9d1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-203', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\r'), ('prefix', '\x981\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-204', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\r'), ('prefix', '\x9e1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-205', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\r'), ('prefix', '\x9f1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-206', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\r'), ('prefix', '\x1b(\x000'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-207', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\r'), ('prefix', '\x1b[1:\x002m'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-208', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\r'), ('prefix', '\x9b1:\x002m'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-209', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\r'), ('prefix', '\x1b[1\x002m'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-210', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\r'), ('prefix', '\x1bP1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-211', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\r'), ('prefix', '\x1b]1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-212', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\r'), ('prefix', '\x1bX1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-213', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\r'), ('prefix', '\x1b^1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-214', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\r'), ('prefix', '\x1b_1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-215', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\r'), ('prefix', '\x901\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-216', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\r'), ('prefix', '\x9d1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-217', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\r'), ('prefix', '\x981\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-218', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\r'), ('prefix', '\x9e1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-219', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\r'), ('prefix', '\x9f1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-220', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\r'), ('prefix', '\x1b(\x000'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-221', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\r'), ('prefix', '\x1b[1:\x002m'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-222', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\r'), ('prefix', '\x9b1:\x002m'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-223', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\r'), ('prefix', '\x1b[1\x002m'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-224', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x11'), ('prefix', '\x1bP1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-225', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x11'), ('prefix', '\x1b]1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-226', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x11'), ('prefix', '\x1bX1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-227', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x11'), ('prefix', '\x1b^1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-228', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x11'), ('prefix', '\x1b_1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-229', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x11'), ('prefix', '\x901\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-230', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x11'), ('prefix', '\x9d1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-231', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x11'), ('prefix', '\x981\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-232', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x11'), ('prefix', '\x9e1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-233', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x11'), ('prefix', '\x9f1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-234', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x11'), ('prefix', '\x1b(\x000'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-235', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x11'), ('prefix', '\x1b[1:\x002m'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-236', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x11'), ('prefix', '\x9b1:\x002m'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-237', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x11'), ('prefix', '\x1b[1\x002m'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-238', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x11'), ('prefix', '\x1bP1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-239', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x11'), ('prefix', '\x1b]1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-240', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x11'), ('prefix', '\x1bX1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-241', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x11'), ('prefix', '\x1b^1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-242', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x11'), ('prefix', '\x1b_1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-243', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x11'), ('prefix', '\x901\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-244', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x11'), ('prefix', '\x9d1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-245', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x11'), ('prefix', '\x981\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-246', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x11'), ('prefix', '\x9e1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-247', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x11'), ('prefix', '\x9f1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-248', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x11'), ('prefix', '\x1b(\x000'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-249', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x11'), ('prefix', '\x1b[1:\x002m'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-250', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x11'), ('prefix', '\x9b1:\x002m'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-251', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x11'), ('prefix', '\x1b[1\x002m'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-252', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x11'), ('prefix', '\x1bP1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-253', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x11'), ('prefix', '\x1b]1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-254', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x11'), ('prefix', '\x1bX1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-255', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x11'), ('prefix', '\x1b^1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-256', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x11'), ('prefix', '\x1b_1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-257', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x11'), ('prefix', '\x901\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-258', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x11'), ('prefix', '\x9d1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-259', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x11'), ('prefix', '\x981\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-260', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x11'), ('prefix', '\x9e1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-261', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x11'), ('prefix', '\x9f1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-262', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x11'), ('prefix', '\x1b(\x000'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-263', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x11'), ('prefix', '\x1b[1:\x002m'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-264', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x11'), ('prefix', '\x9b1:\x002m'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-265', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x11'), ('prefix', '\x1b[1\x002m'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-266', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x11'), ('prefix', '\x1bP1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-267', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x11'), ('prefix', '\x1b]1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-268', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x11'), ('prefix', '\x1bX1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-269', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x11'), ('prefix', '\x1b^1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-270', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x11'), ('prefix', '\x1b_1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-271', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x11'), ('prefix', '\x901\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-272', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x11'), ('prefix', '\x9d1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-273', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x11'), ('prefix', '\x981\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-274', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x11'), ('prefix', '\x9e1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-275', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x11'), ('prefix', '\x9f1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-276', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x11'), ('prefix', '\x1b(\x000'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-277', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x11'), ('prefix', '\x1b[1:\x002m'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-278', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x11'), ('prefix', '\x9b1:\x002m'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-279', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x11'), ('prefix', '\x1b[1\x002m'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-280', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x19'), ('prefix', '\x1bP1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-281', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x19'), ('prefix', '\x1b]1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-282', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x19'), ('prefix', '\x1bX1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-283', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x19'), ('prefix', '\x1b^1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-284', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x19'), ('prefix', '\x1b_1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-285', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x19'), ('prefix', '\x901\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-286', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x19'), ('prefix', '\x9d1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-287', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x19'), ('prefix', '\x981\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-288', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x19'), ('prefix', '\x9e1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-289', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x19'), ('prefix', '\x9f1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-290', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x19'), ('prefix', '\x1b(\x000'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-291', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x19'), ('prefix', '\x1b[1:\x002m'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-292', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x19'), ('prefix', '\x9b1:\x002m'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-293', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x19'), ('prefix', '\x1b[1\x002m'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-294', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x19'), ('prefix', '\x1bP1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-295', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x19'), ('prefix', '\x1b]1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-296', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x19'), ('prefix', '\x1bX1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-297', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x19'), ('prefix', '\x1b^1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-298', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x19'), ('prefix', '\x1b_1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-299', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x19'), ('prefix', '\x901\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-300', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x19'), ('prefix', '\x9d1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-301', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x19'), ('prefix', '\x981\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-302', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x19'), ('prefix', '\x9e1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-303', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x19'), ('prefix', '\x9f1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-304', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x19'), ('prefix', '\x1b(\x000'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-305', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x19'), ('prefix', '\x1b[1:\x002m'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-306', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x19'), ('prefix', '\x9b1:\x002m'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-307', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x19'), ('prefix', '\x1b[1\x002m'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-308', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x19'), ('prefix', '\x1bP1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-309', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x19'), ('prefix', '\x1b]1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-310', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x19'), ('prefix', '\x1bX1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-311', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x19'), ('prefix', '\x1b^1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-312', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x19'), ('prefix', '\x1b_1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-313', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x19'), ('prefix', '\x901\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-314', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x19'), ('prefix', '\x9d1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-315', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x19'), ('prefix', '\x981\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-316', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x19'), ('prefix', '\x9e1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-317', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x19'), ('prefix', '\x9f1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-318', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x19'), ('prefix', '\x1b(\x000'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-319', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x19'), ('prefix', '\x1b[1:\x002m'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-320', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x19'), ('prefix', '\x9b1:\x002m'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-321', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x19'), ('prefix', '\x1b[1\x002m'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-322', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x19'), ('prefix', '\x1bP1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-323', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x19'), ('prefix', '\x1b]1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-324', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x19'), ('prefix', '\x1bX1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-325', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x19'), ('prefix', '\x1b^1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-326', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x19'), ('prefix', '\x1b_1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-327', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x19'), ('prefix', '\x901\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-328', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x19'), ('prefix', '\x9d1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-329', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x19'), ('prefix', '\x981\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-330', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x19'), ('prefix', '\x9e1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-331', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x19'), ('prefix', '\x9f1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-332', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x19'), ('prefix', '\x1b(\x000'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-333', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x19'), ('prefix', '\x1b[1:\x002m'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-334', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x19'), ('prefix', '\x9b1:\x002m'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-335', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x19'), ('prefix', '\x1b[1\x002m'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-336', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x7f'), ('prefix', '\x1bP1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-337', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x7f'), ('prefix', '\x1b]1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-338', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x7f'), ('prefix', '\x1bX1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-339', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x7f'), ('prefix', '\x1b^1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-340', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x7f'), ('prefix', '\x1b_1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-341', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x7f'), ('prefix', '\x901\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-342', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x7f'), ('prefix', '\x9d1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-343', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x7f'), ('prefix', '\x981\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-344', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x7f'), ('prefix', '\x9e1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-345', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x7f'), ('prefix', '\x9f1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-346', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x7f'), ('prefix', '\x1b(\x000'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-347', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x7f'), ('prefix', '\x1b[1:\x002m'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-348', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x7f'), ('prefix', '\x9b1:\x002m'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-349', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x7f'), ('prefix', '\x1b[1\x002m'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-350', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x7f'), ('prefix', '\x1bP1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-351', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x7f'), ('prefix', '\x1b]1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-352', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x7f'), ('prefix', '\x1bX1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-353', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x7f'), ('prefix', '\x1b^1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-354', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x7f'), ('prefix', '\x1b_1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-355', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x7f'), ('prefix', '\x901\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-356', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x7f'), ('prefix', '\x9d1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-357', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x7f'), ('prefix', '\x981\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-358', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x7f'), ('prefix', '\x9e1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-359', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x7f'), ('prefix', '\x9f1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-360', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x7f'), ('prefix', '\x1b(\x000'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-361', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x7f'), ('prefix', '\x1b[1:\x002m'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-362', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x7f'), ('prefix', '\x9b1:\x002m'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-363', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x7f'), ('prefix', '\x1b[1\x002m'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-364', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x7f'), ('prefix', '\x1bP1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-365', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x7f'), ('prefix', '\x1b]1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-366', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x7f'), ('prefix', '\x1bX1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-367', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x7f'), ('prefix', '\x1b^1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-368', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x7f'), ('prefix', '\x1b_1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-369', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x7f'), ('prefix', '\x901\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-370', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x7f'), ('prefix', '\x9d1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-371', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x7f'), ('prefix', '\x981\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-372', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x7f'), ('prefix', '\x9e1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-373', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x7f'), ('prefix', '\x9f1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-374', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x7f'), ('prefix', '\x1b(\x000'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-375', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x7f'), ('prefix', '\x1b[1:\x002m'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-376', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x7f'), ('prefix', '\x9b1:\x002m'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-377', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x7f'), ('prefix', '\x1b[1\x002m'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-378', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x7f'), ('prefix', '\x1bP1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-379', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x7f'), ('prefix', '\x1b]1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-380', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x7f'), ('prefix', '\x1bX1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-381', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x7f'), ('prefix', '\x1b^1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-382', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x7f'), ('prefix', '\x1b_1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-383', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x7f'), ('prefix', '\x901\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-384', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x7f'), ('prefix', '\x9d1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-385', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x7f'), ('prefix', '\x981\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-386', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x7f'), ('prefix', '\x9e1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-387', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x7f'), ('prefix', '\x9f1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-388', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x7f'), ('prefix', '\x1b(\x000'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-389', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x7f'), ('prefix', '\x1b[1:\x002m'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-390', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x7f'), ('prefix', '\x9b1:\x002m'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-391', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x7f'), ('prefix', '\x1b[1\x002m'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-392', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x85'), ('prefix', '\x1bP1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-393', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x85'), ('prefix', '\x1b]1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-394', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x85'), ('prefix', '\x1bX1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-395', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x85'), ('prefix', '\x1b^1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-396', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x85'), ('prefix', '\x1b_1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-397', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x85'), ('prefix', '\x901\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-398', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x85'), ('prefix', '\x9d1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-399', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x85'), ('prefix', '\x981\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-400', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x85'), ('prefix', '\x9e1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-401', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x85'), ('prefix', '\x9f1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-402', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x85'), ('prefix', '\x1b(\x000'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-403', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x85'), ('prefix', '\x1b[1:\x002m'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-404', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x85'), ('prefix', '\x9b1:\x002m'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-405', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x85'), ('prefix', '\x1b[1\x002m'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-406', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x85'), ('prefix', '\x1bP1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-407', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x85'), ('prefix', '\x1b]1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-408', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x85'), ('prefix', '\x1bX1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-409', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x85'), ('prefix', '\x1b^1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-410', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x85'), ('prefix', '\x1b_1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-411', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x85'), ('prefix', '\x901\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-412', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x85'), ('prefix', '\x9d1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-413', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x85'), ('prefix', '\x981\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-414', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x85'), ('prefix', '\x9e1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-415', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x85'), ('prefix', '\x9f1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-416', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x85'), ('prefix', '\x1b(\x000'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-417', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x85'), ('prefix', '\x1b[1:\x002m'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-418', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x85'), ('prefix', '\x9b1:\x002m'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-419', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x85'), ('prefix', '\x1b[1\x002m'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-420', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x85'), ('prefix', '\x1bP1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-421', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x85'), ('prefix', '\x1b]1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-422', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x85'), ('prefix', '\x1bX1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-423', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x85'), ('prefix', '\x1b^1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-424', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x85'), ('prefix', '\x1b_1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-425', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x85'), ('prefix', '\x901\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-426', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x85'), ('prefix', '\x9d1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-427', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x85'), ('prefix', '\x981\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-428', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x85'), ('prefix', '\x9e1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-429', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x85'), ('prefix', '\x9f1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-430', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x85'), ('prefix', '\x1b(\x000'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-431', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x85'), ('prefix', '\x1b[1:\x002m'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-432', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x85'), ('prefix', '\x9b1:\x002m'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-433', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x85'), ('prefix', '\x1b[1\x002m'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-434', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x85'), ('prefix', '\x1bP1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-435', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x85'), ('prefix', '\x1b]1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-436', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x85'), ('prefix', '\x1bX1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-437', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x85'), ('prefix', '\x1b^1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-438', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x85'), ('prefix', '\x1b_1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-439', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x85'), ('prefix', '\x901\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-440', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x85'), ('prefix', '\x9d1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-441', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x85'), ('prefix', '\x981\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-442', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x85'), ('prefix', '\x9e1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-443', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x85'), ('prefix', '\x9f1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-444', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x85'), ('prefix', '\x1b(\x000'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-445', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x85'), ('prefix', '\x1b[1:\x002m'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-446', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x85'), ('prefix', '\x9b1:\x002m'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-447', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x85'), ('prefix', '\x1b[1\x002m'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-448', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x91'), ('prefix', '\x1bP1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-449', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x91'), ('prefix', '\x1b]1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-450', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x91'), ('prefix', '\x1bX1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-451', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x91'), ('prefix', '\x1b^1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-452', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x91'), ('prefix', '\x1b_1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-453', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x91'), ('prefix', '\x901\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-454', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x91'), ('prefix', '\x9d1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-455', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x91'), ('prefix', '\x981\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-456', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x91'), ('prefix', '\x9e1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-457', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x91'), ('prefix', '\x9f1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-458', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x91'), ('prefix', '\x1b(\x000'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-459', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x91'), ('prefix', '\x1b[1:\x002m'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-460', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x91'), ('prefix', '\x9b1:\x002m'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-461', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x91'), ('prefix', '\x1b[1\x002m'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-462', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x91'), ('prefix', '\x1bP1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-463', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x91'), ('prefix', '\x1b]1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-464', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x91'), ('prefix', '\x1bX1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-465', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x91'), ('prefix', '\x1b^1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-466', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x91'), ('prefix', '\x1b_1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-467', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x91'), ('prefix', '\x901\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-468', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x91'), ('prefix', '\x9d1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-469', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x91'), ('prefix', '\x981\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-470', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x91'), ('prefix', '\x9e1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-471', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x91'), ('prefix', '\x9f1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-472', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x91'), ('prefix', '\x1b(\x000'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-473', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x91'), ('prefix', '\x1b[1:\x002m'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-474', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x91'), ('prefix', '\x9b1:\x002m'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-475', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x91'), ('prefix', '\x1b[1\x002m'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-476', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x91'), ('prefix', '\x1bP1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-477', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x91'), ('prefix', '\x1b]1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-478', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x91'), ('prefix', '\x1bX1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-479', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x91'), ('prefix', '\x1b^1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-480', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x91'), ('prefix', '\x1b_1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-481', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x91'), ('prefix', '\x901\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-482', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x91'), ('prefix', '\x9d1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-483', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x91'), ('prefix', '\x981\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-484', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x91'), ('prefix', '\x9e1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-485', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x91'), ('prefix', '\x9f1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-486', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x91'), ('prefix', '\x1b(\x000'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-487', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x91'), ('prefix', '\x1b[1:\x002m'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-488', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x91'), ('prefix', '\x9b1:\x002m'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-489', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x91'), ('prefix', '\x1b[1\x002m'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-490', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x91'), ('prefix', '\x1bP1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-491', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x91'), ('prefix', '\x1b]1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-492', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x91'), ('prefix', '\x1bX1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-493', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x91'), ('prefix', '\x1b^1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-494', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x91'), ('prefix', '\x1b_1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-495', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x91'), ('prefix', '\x901\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-496', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x91'), ('prefix', '\x9d1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-497', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x91'), ('prefix', '\x981\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-498', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x91'), ('prefix', '\x9e1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-499', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x91'), ('prefix', '\x9f1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-500', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x91'), ('prefix', '\x1b(\x000'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-501', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x91'), ('prefix', '\x1b[1:\x002m'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-502', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x91'), ('prefix', '\x9b1:\x002m'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-503', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x91'), ('prefix', '\x1b[1\x002m'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-504', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x99'), ('prefix', '\x1bP1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-505', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x99'), ('prefix', '\x1b]1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-506', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x99'), ('prefix', '\x1bX1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-507', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x99'), ('prefix', '\x1b^1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-508', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x99'), ('prefix', '\x1b_1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-509', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x99'), ('prefix', '\x901\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-510', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x99'), ('prefix', '\x9d1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-511', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x99'), ('prefix', '\x981\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-512', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x99'), ('prefix', '\x9e1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-513', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x99'), ('prefix', '\x9f1\x002'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-514', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x99'), ('prefix', '\x1b(\x000'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-515', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x99'), ('prefix', '\x1b[1:\x002m'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-516', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x99'), ('prefix', '\x9b1:\x002m'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-517', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x99'), ('prefix', '\x1b[1\x002m'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-518', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x99'), ('prefix', '\x1bP1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-519', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x99'), ('prefix', '\x1b]1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-520', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x99'), ('prefix', '\x1bX1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-521', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x99'), ('prefix', '\x1b^1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-522', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x99'), ('prefix', '\x1b_1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-523', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x99'), ('prefix', '\x901\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-524', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x99'), ('prefix', '\x9d1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-525', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x99'), ('prefix', '\x981\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-526', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x99'), ('prefix', '\x9e1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-527', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x99'), ('prefix', '\x9f1\x002'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-528', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x99'), ('prefix', '\x1b(\x000'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-529', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x99'), ('prefix', '\x1b[1:\x002m'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-530', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x99'), ('prefix', '\x9b1:\x002m'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-531', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x99'), ('prefix', '\x1b[1\x002m'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-532', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x99'), ('prefix', '\x1bP1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-533', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x99'), ('prefix', '\x1b]1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-534', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x99'), ('prefix', '\x1bX1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-535', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x99'), ('prefix', '\x1b^1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-536', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x99'), ('prefix', '\x1b_1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-537', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x99'), ('prefix', '\x901\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-538', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x99'), ('prefix', '\x9d1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-539', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x99'), ('prefix', '\x981\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-540', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x99'), ('prefix', '\x9e1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-541', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x99'), ('prefix', '\x9f1\x002'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-542', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x99'), ('prefix', '\x1b(\x000'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-543', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x99'), ('prefix', '\x1b[1:\x002m'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-544', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x99'), ('prefix', '\x9b1:\x002m'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-545', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x99'), ('prefix', '\x1b[1\x002m'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-546', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x99'), ('prefix', '\x1bP1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-547', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x99'), ('prefix', '\x1b]1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-548', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x99'), ('prefix', '\x1bX1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-549', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x99'), ('prefix', '\x1b^1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-550', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x99'), ('prefix', '\x1b_1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-551', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x99'), ('prefix', '\x901\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-552', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x99'), ('prefix', '\x9d1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-553', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x99'), ('prefix', '\x981\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-554', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x99'), ('prefix', '\x9e1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-555', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x99'), ('prefix', '\x9f1\x002'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-556', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x99'), ('prefix', '\x1b(\x000'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-557', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x99'), ('prefix', '\x1b[1:\x002m'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-558', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x99'), ('prefix', '\x9b1:\x002m'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_keeps_header_state_across_ignored_controls-559', 'tests.unit.core.test_primitives.test_display_source_view_keeps_header_state_across_ignored_controls', (('control', '\x99'), ('prefix', '\x1b[1\x002m'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_masks_credentials_partly_consumed_by_csi-0', 'tests.unit.core.test_primitives.test_display_source_view_masks_credentials_partly_consumed_by_csi', (('family', 'aws'), ('prefix', '\x1b['), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_masks_credentials_partly_consumed_by_csi-1', 'tests.unit.core.test_primitives.test_display_source_view_masks_credentials_partly_consumed_by_csi', (('family', 'aws'), ('prefix', '\x1b[1'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_masks_credentials_partly_consumed_by_csi-2', 'tests.unit.core.test_primitives.test_display_source_view_masks_credentials_partly_consumed_by_csi', (('family', 'github'), ('prefix', '\x1b['), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_masks_credentials_partly_consumed_by_csi-3', 'tests.unit.core.test_primitives.test_display_source_view_masks_credentials_partly_consumed_by_csi', (('family', 'github'), ('prefix', '\x1b[1'), ('surface', 'sanitize'))),
    ('nfa-test_display_source_view_masks_credentials_partly_consumed_by_csi-4', 'tests.unit.core.test_primitives.test_display_source_view_masks_credentials_partly_consumed_by_csi', (('family', 'aws'), ('prefix', '\x1b['), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_masks_credentials_partly_consumed_by_csi-5', 'tests.unit.core.test_primitives.test_display_source_view_masks_credentials_partly_consumed_by_csi', (('family', 'aws'), ('prefix', '\x1b[1'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_masks_credentials_partly_consumed_by_csi-6', 'tests.unit.core.test_primitives.test_display_source_view_masks_credentials_partly_consumed_by_csi', (('family', 'github'), ('prefix', '\x1b['), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_masks_credentials_partly_consumed_by_csi-7', 'tests.unit.core.test_primitives.test_display_source_view_masks_credentials_partly_consumed_by_csi', (('family', 'github'), ('prefix', '\x1b[1'), ('surface', 'receipt'))),
    ('nfa-test_display_source_view_masks_credentials_partly_consumed_by_csi-8', 'tests.unit.core.test_primitives.test_display_source_view_masks_credentials_partly_consumed_by_csi', (('family', 'aws'), ('prefix', '\x1b['), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_masks_credentials_partly_consumed_by_csi-9', 'tests.unit.core.test_primitives.test_display_source_view_masks_credentials_partly_consumed_by_csi', (('family', 'aws'), ('prefix', '\x1b[1'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_masks_credentials_partly_consumed_by_csi-10', 'tests.unit.core.test_primitives.test_display_source_view_masks_credentials_partly_consumed_by_csi', (('family', 'github'), ('prefix', '\x1b['), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_masks_credentials_partly_consumed_by_csi-11', 'tests.unit.core.test_primitives.test_display_source_view_masks_credentials_partly_consumed_by_csi', (('family', 'github'), ('prefix', '\x1b[1'), ('surface', 'guidance'))),
    ('nfa-test_display_source_view_masks_credentials_partly_consumed_by_csi-12', 'tests.unit.core.test_primitives.test_display_source_view_masks_credentials_partly_consumed_by_csi', (('family', 'aws'), ('prefix', '\x1b['), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_masks_credentials_partly_consumed_by_csi-13', 'tests.unit.core.test_primitives.test_display_source_view_masks_credentials_partly_consumed_by_csi', (('family', 'aws'), ('prefix', '\x1b[1'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_masks_credentials_partly_consumed_by_csi-14', 'tests.unit.core.test_primitives.test_display_source_view_masks_credentials_partly_consumed_by_csi', (('family', 'github'), ('prefix', '\x1b['), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_masks_credentials_partly_consumed_by_csi-15', 'tests.unit.core.test_primitives.test_display_source_view_masks_credentials_partly_consumed_by_csi', (('family', 'github'), ('prefix', '\x1b[1'), ('surface', 'proposal'))),
    ('nfa-test_display_source_view_masks_only_surviving_characters_and_preserves_context-0', 'tests.unit.core.test_primitives.test_display_source_view_masks_only_surviving_characters_and_preserves_context', ()),
    ('nfa-test_display_ten_million_removed_controls_do_not_build_per_control_state-0', 'tests.unit.core.test_primitives.test_display_ten_million_removed_controls_do_not_build_per_control_state', (('tail', ''),)),
    ('nfa-test_display_ten_million_removed_controls_do_not_build_per_control_state-1', 'tests.unit.core.test_primitives.test_display_ten_million_removed_controls_do_not_build_per_control_state', (('tail', 'safe'),)),
    ('nfa-test_display_ten_million_removed_controls_do_not_build_per_control_state-2', 'tests.unit.core.test_primitives.test_display_ten_million_removed_controls_do_not_build_per_control_state', (('tail', 'secret'),)),
    ('nfa-test_display_unions_canonical_and_source_only_masks-0', 'tests.unit.core.test_primitives.test_display_unions_canonical_and_source_only_masks', (('family', 'aws'),)),
    ('nfa-test_display_unions_canonical_and_source_only_masks-1', 'tests.unit.core.test_primitives.test_display_unions_canonical_and_source_only_masks', (('family', 'github'),)),
    ('nfa-test_display_matches_legacy_output_for_supported_escape_corpus-0', 'tests.unit.cli.test_cli_helpers.test_display_matches_legacy_output_for_supported_escape_corpus', ()),
)

# Historical pytest axis order and explicit labels, without argument values.
# The stable case id selects a row; its ordinal selects these legacy labels so
# existing node ids remain unchanged. Each axis records names, size, and labels.
ORIGINAL_PARAMETER_LAYOUTS = {
    'test_display_escape_boundaries_mask_secrets_on_every_surface': (
        (('surface',), 4, None),
        (('prefix',), 20, ('dcs', 'dcs-csi', 'osc-dcs', 'osc-title-esc7', 'dcs-c1-csi', 'dcs-intermediate-header', 'dcs-parameter-header', 'c1-dcs-parameter-header', 'escape-intermediate-header', 'esc-N', 'esc-O', 'esc-M', 'esc-7', 'esc-8', 'esc-c', 'sos', 'pm', 'apc', 'unknown-escape', 'abandoned-csi')),
    ),
    'test_display_removed_controls_preserve_secret_boundaries': (
        (('code',), 64, None),
    ),
    'test_display_ten_million_removed_controls_do_not_build_per_control_state': (
        (('tail',), 3, None),
    ),
    'test_display_boundary_detection_uses_shared_secret_families': (
        (('value', 'payload'), 7, None),
    ),
    'test_display_provenance_masks_low_entropy_keys_after_every_header': (
        (('surface',), 4, None),
        (('prefix',), 10, ('esc-numeric-final', 'csi-colon-final', 'csi-intermediate-final', 'dcs-parameters', 'nested-dcs-parameters', 'c1-dcs-parameters', 'c1-csi-parameters', 'unsupported-csi-parameters', 'osc-parameters', 'c1-osc-parameters')),
    ),
    'test_display_provenance_masks_overlaps_inside_an_ordinary_match': (
        (('surface',), 4, None),
        (('family',), 2, None),
    ),
    'test_display_provenance_covers_every_string_form_and_header': (
        (('surface',), 4, None),
        (('header',), 3, None),
        (('introducer',), 10, None),
    ),
    'test_display_provenance_overlaps_and_headers_are_independent_in_threads': (
        (('surface',), 4, None),
    ),
    'test_display_source_view_masks_credentials_partly_consumed_by_csi': (
        (('surface',), 4, None),
        (('family',), 2, None),
        (('prefix',), 2, None),
    ),
    'test_display_source_view_keeps_header_state_across_ignored_controls': (
        (('control',), 10, None),
        (('surface',), 4, None),
        (('prefix',), 14, ('dcs', 'osc', 'sos', 'pm', 'apc', 'c1-dcs', 'c1-osc', 'c1-sos', 'c1-pm', 'c1-apc', 'esc-intermediate', 'csi-subparameter', 'c1-csi-subparameter', 'csi-parameter')),
    ),
    'test_display_source_view_accepts_control_only_nonsecret_text': (
        (('value', 'expected'), 3, None),
    ),
    'test_display_deleted_view_masks_consumed_prefix_with_internal_control': (
        (('surface',), 4, None),
        (('family',), 2, None),
        (('inner',), 5, ('cr', 'nul', 'del', 'c1', 'supported-csi')),
        (('prefix',), 2, ('csi', 'csi-parameter')),
    ),
    'test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers': (
        (('surface',), 4, None),
        (('prefix',), 11, ('csi', 'c1-csi', 'esc-intermediate', 'sos', 'pm', 'apc', 'c1-sos', 'c1-pm', 'c1-apc', 'c1-dcs', 'c1-osc')),
    ),
    'test_display_deleted_view_preserves_bel_termination_and_nonsecret_parity': (
        (('introducer',), 2, None),
    ),
    'test_display_renderer_provenance_keeps_control_interrupted_headers': (
        (('surface',), 4, None),
        (('header',), 3, None),
        (('control',), 3, ('bel', 'tab', 'lf')),
    ),
    'test_display_renderer_provenance_recovers_consumed_credential_label': (
        (('surface',), 4, None),
    ),
    'test_display_pem_extents_cover_differently_labelled_nested_body': (
        (('label',), 2, None),
        (('surface',), 4, None),
    ),
    'test_display_source_segments_seal_suppressed_strings': (
        (('surface',), 4, None),
        (('hidden', 'tail'), 3, None),
        (('terminator',), 2, ('bel', 'st')),
        (('introducer',), 2, ('osc', 'dcs')),
    ),
    'test_display_source_segments_do_not_invent_credential_whitespace': (
        (('surface',), 4, None),
        (('head', 'tail'), 2, None),
        (('control',), 4, ('nul', 'cr', 'del', 'c1')),
    ),
    'test_display_source_segments_do_not_join_visible_context_through_hidden_payload': (
        (('surface',), 4, None),
        (('terminator',), 2, ('bel', 'st')),
        (('introducer',), 2, ('osc', 'dcs')),
    ),
    'test_display_source_segments_still_mask_visible_secrets_on_both_sides': (
        (('surface',), 4, None),
        (('terminator',), 2, ('bel', 'st')),
        (('introducer',), 2, ('osc', 'dcs')),
    ),
    'test_display_source_segments_keep_prefixed_secret_context_detectable': (
        (('surface',), 4, None),
        (('value',), 3, None),
    ),
    'test_display_rendered_segments_seal_hidden_token_prefix': (
        (('surface',), 4, None),
        (('terminator',), 2, ('bel', 'st')),
        (('introducer',), 2, ('osc', 'dcs')),
    ),
    'test_display_rendered_segments_preserve_visible_space_inside_nonsecret': (
        (('surface',), 4, None),
        (('control',), 2, ('tab', 'lf')),
    ),
    'test_display_rendered_segments_still_join_fully_removed_controls': (
        (('surface',), 4, None),
        (('control',), 4, ('nul', 'cr', 'del', 'c1')),
    ),
    'test_display_rendered_segments_keep_visible_credential_whitespace': (
        (('surface',), 4, None),
        (('control',), 2, ('tab', 'lf')),
        (('prefix',), 2, ('csi', 'csi-parameter')),
    ),
    'test_display_reassembled_tokens_use_markers_before_caller_redaction': (
        (('prefix',), 2, ('plain', 'color')),
        (('removed',), 3, ('sgr', 'cr', 'nul')),
        (('family',), 2, None),
    ),
    'test_display_unions_canonical_and_source_only_masks': (
        (('family',), 2, None),
    ),
    'test_display_does_not_orphan_value_after_guarding_secret_key_context': (
        (('surface',), 4, None),
    ),
    'test_display_restored_union_masks_before_boundary_changes_or_clipping': (
        (('case',), 3, None),
        (('surface',), 4, None),
    ),
    'test_display_source_guard_cannot_complete_a_new_credential_or_tear_a_mask': (
        (('surface',), 4, None),
    ),
    'test_display_attribution_preserves_ordinary_left_boundary': (
        (('suffix',), 2, None),
    ),
    'test_display_attribution_covers_shared_rule_families': (
        (('surface',), 4, None),
        (('value', 'payload'), 16, None),
    ),
    'test_display_attribution_long_benign_colour_runs_keep_parity': (
        (('count',), 3, None),
    ),
    'test_display_attribution_detection_windows_span_removed_control_gaps': (
        (('surface',), 4, None),
        (('control',), 4, ('nul', 'cr', 'del', 'c1')),
        (('count',), 2, None),
    ),
    'test_display_attribution_masks_overlapping_ordinary_credentials': (
        (('family',), 2, None),
        (('surface',), 4, None),
    ),
    'test_display_attribution_fallback_preserves_ordinary_boundary_and_flags': (
        (('plain',), 2, ('ascii-aws', 'unicode-bearer')),
        (('surface',), 4, None),
    ),
    'test_display_attribution_fallback_keeps_carried_starts': (
        (('surface',), 4, None),
    ),
}


def original_parameters(function_name, cases=None):
    """Build one original's mark from stable table rows and historical labels."""
    if function_name not in ORIGINAL_PARAMETER_LAYOUTS:
        raise ValueError("unknown shared display function")
    layout = ORIGINAL_PARAMETER_LAYOUTS[function_name]
    names = tuple(name for axis_names, _size, _labels in layout for name in axis_names)
    source = CORPUS_CASES if cases is None else cases
    qualname = "tests.unit.core.test_primitives." + function_name
    rows = tuple(row for row in source if row[1] == qualname)
    count = 1
    for _axis_names, size, _labels in layout:
        count *= size
    expected_ids = tuple("nfa-" + function_name + "-" + str(index) for index in range(count))
    if tuple(row[0] for row in rows) != expected_ids:
        raise ValueError("shared display case ids do not match layout")
    parameters = []
    for index, (_case_id, _qualname, arguments) in enumerate(rows):
        values = dict(arguments)
        parts = []
        stride = count
        for axis_names, size, labels in layout:
            stride //= size
            axis_index = (index // stride) % size
            if labels is not None:
                parts.append(labels[axis_index])
            else:
                # Pass raw id parts to pytest; collection applies its escaping.
                parts.extend(str(values[name]) for name in axis_names)
        parameters.append(pytest.param(*(values[name] for name in names), id="-".join(parts)))
    return pytest.mark.parametrize(names, tuple(parameters))


def parametrize_original(function):
    """Bind a defined original to its shared cases without namespace mutation."""
    return original_parameters(function.__name__)(function)


# The table and original_parameters must exist before importing the originals:
# test_primitives binds its marks at the end of its module in either import order.
from tests.unit.core import test_primitives as regressions


UNEDITED_CORPUS_FLOOR = 1430
_IGNORED_MARKS = frozenset({"skip", "skipif", "xfail"})
_TABLES_LOCK = threading.Lock()
# A one-slot list, not a global rebinding: the patch census refuses global statements.
_REAL_TABLES = [None]


def _replay_functions():
    """Unedited display tests, in the registry's historical selector order."""
    selected = [function for name, function in inspect.getmembers(regressions, inspect.isfunction)
                if name.startswith("test_display_") and "monkeypatch" not in inspect.signature(function).parameters]
    selected.append(legacy.test_display_matches_legacy_output_for_supported_escape_corpus)
    return tuple(selected)


def _ignored_skip_marks(function):
    return tuple(mark.name for mark in getattr(function, "pytestmark", ()) if mark.name in _IGNORED_MARKS)


def _function_map():
    return {function.__module__ + "." + function.__name__: function for function in _replay_functions()}


def argument_digest(arguments):
    """Digest argument values. The case id and the qualname are compared beside it."""
    payload = json.dumps(dict(arguments), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


_PARAMETER_SET = type(pytest.param(1))


def _parametrize_marks(function):
    holder = getattr(function, "pytestmark", ())
    if not isinstance(holder, (list, tuple)):
        holder = (holder,)
    return tuple(mark for mark in holder if getattr(mark, "name", None) == "parametrize")


def _mark_rows(mark, qualname):
    """Return (argument dicts, error) for one parametrize mark.

    The error names the function. It does not include the argument text.
    """
    if len(getattr(mark, "args", ())) < 2:
        return None, ("parametrize-width", qualname)
    argnames, argvalues = mark.args[0], mark.args[1]
    if isinstance(argnames, str):
        names = tuple(part.strip() for part in argnames.split(",") if part.strip())
        force_tuple = len(names) == 1 and not argnames.rstrip().endswith(",")
    elif isinstance(argnames, (list, tuple)) and all(isinstance(name, str) and name for name in argnames):
        names = tuple(argnames)
        force_tuple = False
    else:
        return None, ("parametrize-names", qualname)
    if not names or len(names) != len(set(names)):
        return None, ("parametrize-names", qualname)
    if not isinstance(argvalues, (list, tuple)):
        return None, ("parametrize-width", qualname)
    if len(argvalues) == 0:
        return None, ("empty-parametrize", qualname)
    rows = []
    for value in argvalues:
        if isinstance(value, _PARAMETER_SET):
            values = tuple(value.values)
        elif force_tuple:
            values = (value,)
        elif isinstance(value, (list, tuple)):
            values = tuple(value)
        else:
            return None, ("parametrize-width", qualname)
        if len(values) != len(names):
            return None, ("parametrize-width", qualname)
        rows.append(dict(zip(names, values)))
    return rows, None


def _expand_parametrize(function, qualname):
    """Cartesian product in pytest's decorator order.

    The mark closest to the function is stored first and varies slowest.
    Each later mark varies fastest, which is the order pytest collects.
    """
    product = [{}]
    seen_names = set()
    for mark in _parametrize_marks(function):
        rows, error = _mark_rows(mark, qualname)
        if error is not None:
            return None, error
        names = tuple(rows[0])
        if any(name in seen_names for name in names):
            return None, ("parametrize-names", qualname)
        seen_names.update(names)
        product = [{**old, **new} for old in product for new in rows]
    return product, None


def original_call_cases(functions=None):
    """Read each original test's parametrize marks into stable case rows.

    A function with no parametrize mark is one call and no arguments. The id
    is nfa-<function>-<index> in collected order, the same id CORPUS_CASES uses.
    """
    selected = _replay_functions() if functions is None else tuple(functions)
    cases = []
    errors = []
    for function in selected:
        qualname = function.__module__ + "." + function.__name__
        product, error = _expand_parametrize(function, qualname)
        if error is not None:
            errors.append(error)
            continue
        for index, arguments in enumerate(product):
            cases.append(("nfa-" + function.__name__ + "-" + str(index), qualname,
                          tuple(sorted(arguments.items()))))
    return tuple(cases), tuple(errors)


def _guard_digest(arguments):
    """Digest a case whose values are str or int. Any other shape has no digest."""
    if isinstance(arguments, dict):
        pairs = arguments
    elif isinstance(arguments, (list, tuple)):
        if any(not isinstance(item, tuple) or len(item) != 2 or not isinstance(item[0], str)
               for item in arguments):
            return None
        if len({item[0] for item in arguments}) != len(arguments):
            return None
        pairs = dict(arguments)
    else:
        return None
    if any(not isinstance(value, (str, int)) or isinstance(value, bool) for value in pairs.values()):
        return None
    return argument_digest(pairs)


def _duplicate_ids(ids):
    seen = set()
    duplicated = []
    for case_id in ids:
        if case_id in seen:
            if case_id not in duplicated:
                duplicated.append(case_id)
        else:
            seen.add(case_id)
    return tuple(duplicated)


def shared_table_errors(table, originals):
    """Refuse a table and an original parametrization that disagree.

    An original row removed, substituted, or added fails, and so does a table
    row with no original. Comparison is by case id and argument digest in both
    directions. The tuples name the failure kind and the case id, not the
    argument text. A rejected candidate leaves the recorded table unchanged.
    """
    errors = []
    table_ids = tuple(row[0] for row in table)
    original_ids = tuple(row[0] for row in originals)
    table_dup = _duplicate_ids(table_ids)
    original_dup = _duplicate_ids(original_ids)
    if table_dup:
        errors.append(("duplicate-id", "table", table_dup))
    if original_dup:
        errors.append(("duplicate-id", "original", original_dup))
    if table_ids != original_ids:
        table_set = set(table_ids)
        original_set = set(original_ids)
        missing_from_table = tuple(case_id for case_id in original_ids if case_id not in table_set)
        missing_from_original = tuple(case_id for case_id in table_ids if case_id not in original_set)
        if missing_from_table or missing_from_original:
            errors.append(("ids", missing_from_table, missing_from_original))
        else:
            errors.append(("order",))
    table_map = {}
    for case_id, qualname, arguments in table:
        table_map.setdefault(case_id, (qualname, arguments))
    original_map = {}
    for case_id, qualname, arguments in originals:
        original_map.setdefault(case_id, (qualname, arguments))
    for case_id in table_ids:
        if case_id not in original_map or case_id not in table_map:
            continue
        table_name, table_arguments = table_map[case_id]
        original_name, original_arguments = original_map[case_id]
        if table_name != original_name:
            errors.append(("function", case_id))
        table_digest = _guard_digest(table_arguments)
        original_digest = _guard_digest(original_arguments)
        if table_digest is None or original_digest is None:
            errors.append(("digest-type", case_id))
        elif table_digest != original_digest:
            errors.append(("digest", case_id))
    return tuple(errors)


def replay_parameters(cases=None):
    """Replay parameters for the explicit table, in table order."""
    source = CORPUS_CASES if cases is None else cases
    functions = _function_map()
    return tuple(pytest.param(functions[qualname], dict(arguments), id=case_id)
                 for case_id, qualname, arguments in source if qualname in functions)


def corpus_case_errors(cases, baseline, floor):
    """Refuse a removed, reordered, or substituted case before any case runs.

    A copied row keeps the function names and the case count, so the id sequence
    and the argument digest are what refuse it. The floor is an extra check.
    The returned tuples name the case id and the failure kind, not the argument
    text. A rejected candidate leaves the recorded table unchanged, and the next
    call checks that table again.
    """
    errors = []
    ids = tuple(case_id for case_id, _qualname, _arguments in cases)
    recorded_ids = tuple(case_id for case_id, _qualname, _digest in baseline)
    if len(set(recorded_ids)) != len(recorded_ids):
        errors.append(("baseline-duplicate-id",))
    if len(cases) < floor:
        errors.append(("floor", len(cases), floor))
    if ids != recorded_ids:
        id_set = set(ids)
        recorded_set = set(recorded_ids)
        missing = tuple(case_id for case_id in recorded_ids if case_id not in id_set)
        extra = tuple(case_id for case_id in ids if case_id not in recorded_set)
        if missing or extra:
            errors.append(("ids", missing, extra))
        else:
            errors.append(("order",))
    seen = set()
    duplicated = []
    for case_id in ids:
        if case_id in seen:
            if case_id not in duplicated:
                duplicated.append(case_id)
        else:
            seen.add(case_id)
    if duplicated:
        errors.append(("duplicate-id", tuple(duplicated)))
    recorded = {case_id: (qualname, digest) for case_id, qualname, digest in baseline}
    for case_id, qualname, arguments in cases:
        expected = recorded.get(case_id)
        if expected is None:
            continue
        expected_name, expected_digest = expected
        if qualname != expected_name:
            errors.append(("function", case_id))
        if argument_digest(arguments) != expected_digest:
            errors.append(("digest", case_id))
    return tuple(errors)


def replay_list_errors(functions, required, cases, floor):
    """Refuse a renamed, skipped, or shrunk corpus before any case runs."""
    names = tuple(function.__module__ + "." + function.__name__ for function in functions)
    errors = []
    if names != tuple(required):
        errors.append(("registry", names, tuple(required)))
    for function in functions:
        marks = _ignored_skip_marks(function)
        if marks:
            errors.append((function.__name__, marks))
    if len(cases) < floor:
        errors.append(("floor", len(cases), floor))
    return tuple(errors)


UNEDITED_CORPUS = replay_parameters()


def real_attribution_tables():
    """Return one production compile. A failed compile is not cached.

    Concurrent callers block until that compile finishes or raises, then share
    the tuple from the successful call. The next caller retries a failure.
    """
    with _TABLES_LOCK:
        if _REAL_TABLES[0] is None:
            _REAL_TABLES[0] = primitives._display_attribution_tables()
        return _REAL_TABLES[0]


def install_nfa_replay(monkeypatch, checked):
    """Serve the compiled graph and the parity wrapper without compiling again."""
    width, graph, _matcher = real_attribution_tables()

    def tables():
        return width, graph, checked

    monkeypatch.setattr("aegis_core.primitives._display_attribution_tables", tables)
    monkeypatch.setattr("aegis_core.display_attribution.may_match_visible", checked)
    return graph


def nfa_checked(original):
    """Compare production memo acceptance with the NFA, then return the NFA result."""
    def checked(grammar, text, runs, charge, **kwargs):
        expected = original(grammar, text, runs, lambda _: True, memoize=False, **kwargs)
        assert original(grammar, text, runs, lambda _: True, **kwargs) == expected
        return original(grammar, text, runs, charge, memoize=False, **kwargs)

    return checked


def test_unedited_regression_corpus_meets_floor():
    assert replay_list_errors(_replay_functions(), REPLAY_FUNCTIONS, UNEDITED_CORPUS,
                              UNEDITED_CORPUS_FLOOR) == ()
    assert corpus_case_errors(CORPUS_CASES, ROUND1_CASE_BASELINE, UNEDITED_CORPUS_FLOOR) == ()


def test_corpus_floor_rejects_shrinkage_rename_and_skip():
    functions = _replay_functions()
    renamed = replay_list_errors(functions, REPLAY_FUNCTIONS[:-1], UNEDITED_CORPUS, UNEDITED_CORPUS_FLOOR)
    assert renamed and renamed[0][0] == "registry"
    shrunk = UNEDITED_CORPUS[:UNEDITED_CORPUS_FLOOR - 1]
    assert replay_list_errors(functions, REPLAY_FUNCTIONS, shrunk, UNEDITED_CORPUS_FLOOR) == (
        ("floor", UNEDITED_CORPUS_FLOOR - 1, UNEDITED_CORPUS_FLOOR),)

    @pytest.mark.xfail
    @pytest.mark.skipif(False, reason="held")
    @pytest.mark.skip(reason="held")
    def skipped():
        pass

    name = skipped.__module__ + "." + skipped.__name__
    assert replay_list_errors((skipped,), (name,), (), 0) == ((skipped.__name__, ("skip", "skipif", "xfail")),)


def test_replay_keeps_only_the_nfa_axis():
    assert "memoize" not in inspect.signature(test_unedited_regression_corpus_memo_parity).parameters
    assert [case_id for case_id, _qualname, _arguments in CORPUS_CASES] == [
        case_id for case_id, _qualname, _digest in ROUND1_CASE_BASELINE]
    assert all(case_id.startswith("nfa-") for case_id, _qualname, _arguments in CORPUS_CASES)


def test_replay_is_generated_from_the_shared_table():
    replay = replay_parameters()
    assert [param.id for param in replay] == [case_id for case_id, _qualname, _arguments in CORPUS_CASES]
    for param, (case_id, qualname, arguments) in zip(replay, CORPUS_CASES):
        function, args = param.values
        assert param.id == case_id
        assert function.__module__ + "." + function.__name__ == qualname
        assert args == dict(arguments)


def _aws_case_id():
    return "nfa-test_display_attribution_covers_shared_rule_families-0"


def _substitute_aws_row(cases):
    aws_id = _aws_case_id()
    aws = next(row for row in cases if row[0] == aws_id)
    donor = next(arguments for case_id, qualname, arguments in cases
                 if qualname == aws[1] and case_id != aws_id and dict(arguments).get("value") != dict(aws[2]).get("value"))
    return tuple((case_id, qualname, donor if case_id == aws_id else arguments)
                 for case_id, qualname, arguments in cases)


def test_removal_and_duplicate_substitution_fail():
    aws_id = _aws_case_id()
    substituted = _substitute_aws_row(CORPUS_CASES)
    assert len(substituted) == UNEDITED_CORPUS_FLOOR
    # Names, marks, and the count stay valid. The digest is the check that fires.
    assert replay_list_errors(_replay_functions(), REPLAY_FUNCTIONS, replay_parameters(substituted),
                              UNEDITED_CORPUS_FLOOR) == ()
    assert corpus_case_errors(substituted, ROUND1_CASE_BASELINE, UNEDITED_CORPUS_FLOOR) == (("digest", aws_id),)
    removed = tuple(row for row in CORPUS_CASES if row[0] != aws_id)
    assert corpus_case_errors(removed, ROUND1_CASE_BASELINE, UNEDITED_CORPUS_FLOOR) == (
        ("floor", UNEDITED_CORPUS_FLOOR - 1, UNEDITED_CORPUS_FLOOR), ("ids", (aws_id,), ()),)
    copied = (CORPUS_CASES[0],) + CORPUS_CASES
    duplicated = corpus_case_errors(copied, ROUND1_CASE_BASELINE, 1)
    assert any(item[0] == "duplicate-id" and CORPUS_CASES[0][0] in item[1] for item in duplicated)
    assert any(item[0] == "order" for item in duplicated)
    assert corpus_case_errors(CORPUS_CASES, ROUND1_CASE_BASELINE, UNEDITED_CORPUS_FLOOR) == ()


def test_original_parametrizations_match_the_shared_table():
    originals, errors = original_call_cases()
    assert errors == ()
    differences = shared_table_errors(CORPUS_CASES, originals)
    assert differences == (), f"Original/table cases differ: {differences!r}"


# Ordered node-id tails of the pre-#686 originals, captured independently of
# ORIGINAL_PARAMETER_LAYOUTS under pytest 8.3.4 (importlib, collect-only, no
# xdist, no cache). Each row is the function, the collected count, and the
# sha256 of those tails in collection order. A tail is the node id after "::".
# The digest is length-prefixed UTF-8, so a label change cannot hide inside a
# joined line. Argument parity stays on the nfa- ordinal ids.
_NODE_ID_LIMIT = 2048
_TAIL_LIMIT = 4096
_DIGEST_BUDGET = 1048576
_SOURCE_LIMIT = 65536
_COLLECTION_LOCK = threading.Lock()
_COLLECTION_SERIAL = [0]
PRE686_NODE_BASELINE = (
    ("test_display_escape_boundaries_mask_secrets_on_every_surface", 80, "da1b5cdc9c8fe991668847e292ab714727a40d0cd4311c9b371a5cc3e2e657bd"),
    ("test_display_removed_controls_preserve_secret_boundaries", 64, "ce2af8e5ea6f72b71aed8587c782161ef8329da7933d9f676ccb91b331fb3be4"),
    ("test_display_ten_million_removed_controls_do_not_build_per_control_state", 3, "ac5d555fc339bdd7a88ae5831a1a4bea5ea9ce8e7e89c31cfe383e46a26ec8d4"),
    ("test_display_boundary_detection_uses_shared_secret_families", 7, "8a1c7fed6810a0841476cfacdd45b8ac55da818193758ae45995f239da4439dd"),
    ("test_display_provenance_masks_low_entropy_keys_after_every_header", 40, "5bfc0f75d57461574f7e6c52cacda56244eee65525a230a46c9374e7352eb4fd"),
    ("test_display_provenance_masks_overlaps_inside_an_ordinary_match", 8, "b7e9fd6053828e3e3a0ee3c958649e32309b3e91282823ac8d733582a48e514e"),
    ("test_display_provenance_covers_every_string_form_and_header", 120, "e5b53c0a4536ea7ce2a32f2d9ddcc5bde6f996ea9240d47a130bc10654d406e4"),
    ("test_display_provenance_overlaps_and_headers_are_independent_in_threads", 4, "6015ea03ed39659a7f1ce1291b0ab815202da4c26359e19e3d91de4dcb4e5cfa"),
    ("test_display_source_view_masks_credentials_partly_consumed_by_csi", 16, "ea07eec8cbad1912baee7a1576f835a63a76c47f0f538669210b87c8fa1755fe"),
    ("test_display_source_view_keeps_header_state_across_ignored_controls", 560, "3c8cdb8ae659fbd82680314b0315a6bc71596d7cc62e9577e0024631528bcb60"),
    ("test_display_source_view_accepts_control_only_nonsecret_text", 3, "55fc337fdebdc0c0d1b19c13755f78690f5d7c05842166fda6a4539a0971b13c"),
    ("test_display_deleted_view_masks_consumed_prefix_with_internal_control", 80, "06db41919cd92e60b8d875cf5525ad977a0014bfdc39a150e9dd88f0a328b821"),
    ("test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers", 44, "36b097f4861a6e28fa5ee55986bfabfab36f43410b3e6b590a59b0a050102ca8"),
    ("test_display_deleted_view_preserves_bel_termination_and_nonsecret_parity", 2, "faad7a76ab68da8e621aab320a2eb8efcc92f66a481597128e4f046922f4673d"),
    ("test_display_renderer_provenance_keeps_control_interrupted_headers", 36, "eeda24284514f7d5e2f4690acae4ceebc642a025540396924333a4d2c43a82b3"),
    ("test_display_renderer_provenance_recovers_consumed_credential_label", 4, "7e6fa3f3db23f39a3b31d857a6219fc107ac6896ecdcce667592eae342939967"),
    ("test_display_pem_extents_cover_differently_labelled_nested_body", 8, "fcad3c0f17a8d1656b0062409613b1da90aea6cfd9f6db62abe77da310da4ce2"),
    ("test_display_source_segments_seal_suppressed_strings", 48, "9bfeba48f836db46be8e28f4fa664b71f2b953f1402bb9b30cb29f6a5a0a5b51"),
    ("test_display_source_segments_do_not_invent_credential_whitespace", 32, "bd5ba73a086a1e81b0cbe63de47ddfed0cab6b77bbcd6a66e234d49ba73d12c6"),
    ("test_display_source_segments_do_not_join_visible_context_through_hidden_payload", 16, "a83164c3549af907f5cd184d423174a8c1eca96a39cf0f734e44e0462ebefaed"),
    ("test_display_source_segments_still_mask_visible_secrets_on_both_sides", 16, "77c1ad28bc5a613b276fe61be5a1b0f1113a568dbfda76f7b389aa9092993f4c"),
    ("test_display_source_segments_keep_prefixed_secret_context_detectable", 12, "33165d50f1c9cad4cb6acc3be75d01fad7644d3d44e155905bf60317551e1b36"),
    ("test_display_rendered_segments_seal_hidden_token_prefix", 16, "1e2e3dabb399026b339e9d8d322fdd89ab66f346b82891bf9c937a7a9c5cb9d1"),
    ("test_display_rendered_segments_preserve_visible_space_inside_nonsecret", 8, "b0e64ae5f9f587b773a106ebdb3f28d271124bf0253e2e939585355be20dde5c"),
    ("test_display_rendered_segments_still_join_fully_removed_controls", 16, "ca41b56f80e1f99843d488e67d29db5048838d3b4a830d832bfe3be10e90ba1f"),
    ("test_display_rendered_segments_keep_visible_credential_whitespace", 16, "0ee33d13b3f159115088f3f344b9cae8bf25c26af521f7436e9d81232d404f0d"),
    ("test_display_reassembled_tokens_use_markers_before_caller_redaction", 12, "f4d8c3d655e96edcb17abf2031bc939419bd50ec6a2e180322bdf68b8c5e62ad"),
    ("test_display_unions_canonical_and_source_only_masks", 2, "2bfe80daca5586806d0cc25cdba4673fe0178c16b619af0719111c3126abe865"),
    ("test_display_does_not_orphan_value_after_guarding_secret_key_context", 4, "27313da70148bd4509f0072de493216c306fa45f1676af730981e7b11c9a0f64"),
    ("test_display_restored_union_masks_before_boundary_changes_or_clipping", 12, "b654983622f6c4a89c98f2a2285f02e9b86859dc9cbce7a9f07a53f16d65ca33"),
    ("test_display_source_guard_cannot_complete_a_new_credential_or_tear_a_mask", 4, "14639b9ca9152e6751c8ea123d9d0c2894afbae0c2e59b55ac65bbdcb945053b"),
    ("test_display_attribution_preserves_ordinary_left_boundary", 2, "f72a1559ffedb201949e57cede14e3ec21aafa7dc2ec4f311a36b068cfc6e8ae"),
    ("test_display_attribution_covers_shared_rule_families", 64, "684c46fe8cfd16ba37b94e0b9d82ee52bd1a7fc383822adfefa2c1b9c7717426"),
    ("test_display_attribution_long_benign_colour_runs_keep_parity", 3, "576f38612da122910d2ceedd5b1c1d04bfb58b0ee1fcc852634494668bb8de6d"),
    ("test_display_attribution_detection_windows_span_removed_control_gaps", 32, "a6a1e5ce5dff8796dd88d62166e15699b7ce16e0071459c451cd23eb2de1da11"),
    ("test_display_attribution_masks_overlapping_ordinary_credentials", 8, "be40b1f77262c9f823a8d26ce81f928ac6dd728099bfbc670c35d78654f13969"),
    ("test_display_attribution_fallback_preserves_ordinary_boundary_and_flags", 8, "e0d20864f7ec30c563f555bffa4809cce23e643313585036df804f7f90c1d942"),
    ("test_display_attribution_fallback_keeps_carried_starts", 4, "8ffa9cdce33a3d089fb31bfad94958a5149abd8f2efd1d870a4e81c5e48b8031"),
)


def _node_id_digest(ids):
    """Hash ordered node-id tails. Oversized or non-text input has no digest."""
    blob = bytearray()
    for item in ids:
        if not isinstance(item, str):
            return None
        raw = item.encode("utf-8")
        if len(raw) > _TAIL_LIMIT or len(blob) + 4 + len(raw) > _DIGEST_BUDGET:
            return None
        blob.extend(len(raw).to_bytes(4, "big"))
        blob.extend(raw)
    return hashlib.sha256(bytes(blob)).hexdigest()


def _group_node_tails(nodeids):
    """Group collected node ids by function, in collection order.

    The tail after '::' is what a label renames. A non-identifier name or an
    oversized tail is a refusal and is not kept.
    """
    grouped = []
    positions = {}
    for nodeid in nodeids:
        if not isinstance(nodeid, str) or "::" not in nodeid:
            return None, ("node-id",)
        tail = nodeid.split("::", 1)[1]
        if len(tail.encode("utf-8")) > _TAIL_LIMIT:
            return None, ("limit",)
        name = tail.split("[", 1)[0]
        if not name.isidentifier():
            return None, ("node-id",)
        slot = positions.get(name)
        if slot is None:
            positions[name] = len(grouped)
            grouped.append((name, [tail]))
        elif slot != len(grouped) - 1:
            return None, ("duplicate", name)
        else:
            grouped[slot][1].append(tail)
    return tuple((name, tuple(tails)) for name, tails in grouped), None


def node_id_errors(collected, baseline):
    """Compare ordered node-id tails to the pre-rewire baseline.

    collected is a tuple of (function name, ordered tails). baseline rows are
    (function name, count, digest). Errors name the function and the kind.
    They do not include node-id text. A rejected candidate leaves the baseline
    unchanged.
    """
    errors = []
    if len(collected) != len(baseline):
        errors.append(("registry", len(collected), len(baseline)))
    for got, expected in zip(collected, baseline):
        name, tails = got
        expected_name, count, digest = expected
        if name != expected_name:
            errors.append(("function", expected_name))
            continue
        if not isinstance(tails, tuple) or len(tails) != count:
            errors.append(("count", name))
            continue
        actual = _node_id_digest(tails)
        if actual is None:
            errors.append(("digest-type", name))
        elif actual != digest:
            errors.append(("digest", name))
    return tuple(errors)


def _next_collection_stem():
    """Process-unique module stem. Caller holds _COLLECTION_LOCK.

    Pytest's importlib mode reuses a module name without executing the new
    file. A stem taken from the directory name collides when two collections
    share a basename, so the stem is a process-local counter instead.
    """
    _COLLECTION_SERIAL[0] += 1
    return "test_ids_n" + str(_COLLECTION_SERIAL[0])


def _open_text_sink():
    """Open os.devnull. The descriptor is closed when os.fdopen fails."""
    descriptor = os.open(os.devnull, os.O_WRONLY)
    try:
        return os.fdopen(descriptor, "w", encoding="utf-8", closefd=True)
    except Exception:
        os.close(descriptor)
        raise


def _quiet_pytest_main(argv, plugins):
    """Run pytest.main without printing node ids or import failures.

    Collection text can embed argument strings. Callers receive only the exit
    code and the in-process capture plugin. The sink is closed on every path.
    """
    sink = None
    old_out = sys.stdout
    old_err = sys.stderr
    try:
        sink = _open_text_sink()
        sys.stdout = sink
        sys.stderr = sink
        return pytest.main(argv, plugins=plugins)
    finally:
        sys.stdout = old_out
        sys.stderr = old_err
        if sink is not None:
            sink.close()


class _CollectionSession:
    """Hold the pytest session. Node ids are read only after pytest.main returns."""

    def __init__(self):
        self.session = None

    def pytest_sessionstart(self, session):
        # The session object only. Item ids stay mutable until every collection
        # hook, including hookwrapper code after yield, has finished.
        self.session = session


def _item_function_name(item):
    """Function name pytest collected, without a parameter id."""
    name = getattr(item, "originalname", None)
    if isinstance(name, str):
        return name
    raw_name = getattr(item, "name", "")
    if not isinstance(raw_name, str):
        return ""
    return raw_name.split("[", 1)[0]


def _final_node_ids(session, limit, allowed=None):
    """Filter, order, and limit the session's final items.

    Call only after pytest.main returns. allowed is the set of original
    function names, or None to keep every item (the import-failure probe).
    A count above limit is refused before ids are stored. On the filtered
    path a non-text id or an oversized tail is also a refusal and stores
    nothing. A missing session contributes no ids.
    """
    if session is None:
        return (), None
    items = getattr(session, "items", None)
    if not isinstance(items, list):
        return None, ("collection", "raised")
    if allowed is None:
        if len(items) > limit:
            return None, ("limit",)
        return tuple(getattr(item, "nodeid", None) for item in items), None
    kept = []
    for item in items:
        if _item_function_name(item) not in allowed:
            continue
        if len(kept) >= limit:
            return None, ("limit",)
        nodeid = getattr(item, "nodeid", None)
        if not isinstance(nodeid, str) or "::" not in nodeid:
            return None, ("node-id",)
        tail = nodeid.split("::", 1)[1]
        if len(tail) > _TAIL_LIMIT or len(tail.encode("utf-8")) > _TAIL_LIMIT:
            return None, ("limit",)
        kept.append(nodeid)
    return tuple(kept), None


def _collection_result(session, status, limit, allowed=None):
    """Apply the post-return filter, then the exit status, then grouping."""
    try:
        nodeids, id_error = _final_node_ids(session, limit, allowed)
    except Exception:
        return None, ("collection", "raised")
    if id_error is not None:
        return None, id_error
    if status != pytest.ExitCode.OK:
        return None, ("collection", int(status))
    return _group_node_tails(nodeids)


def _collect_module(directory, source, limit, stem):
    """Collect caller-supplied source. This is the import-failure probe only.

    The original-module guard does not use this path. A nonzero status or an
    import failure is ("collection", code). The code is the pytest exit status,
    or "raised" when pytest itself raises. Output text is not returned. More
    items than limit are refused before their ids are stored. Ids are read
    from the session after pytest.main returns.
    """
    encoded = source.encode("utf-8")
    if len(encoded) > _SOURCE_LIMIT:
        return None, ("limit",)
    if not isinstance(stem, str) or not stem.isidentifier():
        return None, ("node-id",)
    try:
        directory.mkdir(parents=True)
    except OSError:
        return None, ("collection", "raised")
    path = directory / (stem + ".py")
    config = directory / "pytest.ini"
    try:
        path.write_text(source, encoding="utf-8")
        config.write_text("[pytest]\n", encoding="utf-8")
    except OSError:
        return None, ("collection", "raised")

    holder = _CollectionSession()
    saved_path = list(sys.path)
    try:
        try:
            status = _quiet_pytest_main(
                ["--collect-only", "-q", "-n", "0", "-o", "addopts=",
                 "--import-mode=importlib", "-p", "no:cacheprovider",
                 "-c", str(config), "--confcutdir", str(directory),
                 "--basetemp", str(directory / "run"), str(path)],
                [holder])
        except Exception:
            return None, ("collection", "raised")
    finally:
        sys.path[:] = saved_path
    return _collection_result(holder.session, status, limit)


def _fixture_label_error(label):
    """Refuse a fixture id that is not one safe line. Never join lines."""
    if label is None:
        return None
    if not isinstance(label, str) or not label or len(label) > 64:
        return ("node-id",)
    for character in label:
        if character in "\r\n[]:/" or ord(character) <= 32 or ord(character) == 127:
            return ("node-id",)
        if not (character.isalnum() or character in "_.-"):
            return ("node-id",)
    return None


def _original_targets(functions):
    """Names to retain, plus callables that are not the live module objects."""
    names = set()
    replacements = {}
    for function in functions:
        name = getattr(function, "__name__", None)
        if not isinstance(name, str) or not name.isidentifier():
            return None, None, ("node-id",)
        if name in names:
            return None, None, ("duplicate", name)
        names.add(name)
        current = getattr(regressions, name, None)
        if current is not function:
            replacements[name] = function
    return names, replacements, None


def _singleton_label_plugin(label):
    """One autouse fixture value, the same shape as a params id on _fake_home."""
    @pytest.fixture(autouse=True, params=[pytest.param(None, id=label)])
    def _original_node_guard_label():
        return None

    return type("OriginalNodeLabel", (), {
        "_original_node_guard_label": staticmethod(_original_node_guard_label),
    })()


class _PostYieldLayoutLabel:
    """Relabel primitives items after collection wrappers resume.

    The suffix lands on the live item after yield. The guard reads the
    session's final items only after pytest.main returns, so this label
    changes the compared selectors.
    """

    @pytest.hookimpl(hookwrapper=True)
    def pytest_collection_modifyitems(self, items):
        yield
        for item in items:
            path = getattr(item, "path", None)
            if getattr(path, "name", None) == "test_primitives.py":
                item._nodeid += "-layout"


class _ReplaceCollectedCallables:
    """Collect a substituted callable with the real module's fixture closure."""

    def __init__(self, replacements):
        self.replacements = replacements

    @pytest.hookimpl(tryfirst=True)
    def pytest_pycollect_makeitem(self, collector, name, obj):
        replacement = self.replacements.get(name)
        if replacement is None:
            return None
        generated = getattr(collector, "_genfunctions", None)
        if generated is None:
            return []
        return list(generated(name, replacement))


def _collect_real_originals(directory, allowed, replacements, limit, fixture_label,
                            post_yield_relabel=False, collection_plugin=None):
    """Collect the entire module and keep the requested names in observed order.

    Root discovery loads the repository conftest hooks. The session is retained
    and its final items are filtered only after pytest.main returns.
    """
    module_path = getattr(regressions, "__file__", None)
    if not allowed or not isinstance(module_path, str) or not module_path.endswith(".py"):
        return None, ("collection", "raised")
    try:
        directory.mkdir(parents=True)
    except OSError:
        return None, ("collection", "raised")

    holder = _CollectionSession()
    plugins = [holder]
    if replacements:
        plugins.append(_ReplaceCollectedCallables(replacements))
    if fixture_label is not None:
        plugins.append(_singleton_label_plugin(fixture_label))
    if post_yield_relabel:
        plugins.append(_PostYieldLayoutLabel())
    if collection_plugin is not None:
        plugins.append(collection_plugin)
    argv = ["--collect-only", "-q", "-n", "0", "-o", "addopts=",
            "--import-mode=importlib", "-p", "no:cacheprovider",
            "--basetemp", str(directory / "run"), module_path]
    saved_path = list(sys.path)
    try:
        try:
            status = _quiet_pytest_main(argv, plugins)
        except Exception:
            return None, ("collection", "raised")
    finally:
        sys.path[:] = saved_path
    return _collection_result(holder.session, status, limit, allowed)


def collect_original_node_ids(directory, functions, source=None, limit=_NODE_ID_LIMIT,
                              fixture_label=None, post_yield_relabel=False, *, collection_plugin=None):
    """Collect the live original module, including its fixtures and hooks.

    Callers share one lock. A caller-supplied source string is only the
    import-failure probe. A callable that is not the live function is collected
    from the real module so its fixture closure still applies. The optional
    collection plugin applies only to the live module.
    """
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 0:
        return None, ("limit",)
    label_error = _fixture_label_error(fixture_label)
    if label_error is not None:
        return None, label_error
    if post_yield_relabel is not True and post_yield_relabel is not False:
        return None, ("node-id",)
    with _COLLECTION_LOCK:
        if source is not None:
            if fixture_label is not None or post_yield_relabel or collection_plugin is not None:
                return None, ("node-id",)
            stem = _next_collection_stem()
            return _collect_module(directory, source, limit, stem)
        allowed, replacements, error = _original_targets(functions)
        if error is not None:
            return None, error
        return _collect_real_originals(
            directory, allowed, replacements, limit, fixture_label, post_yield_relabel,
            collection_plugin)


def bound_original_functions():
    """The rewired originals, in the pre-#686 collection order."""
    names = tuple(name for name, _count, _digest in PRE686_NODE_BASELINE)
    if set(names) != set(ORIGINAL_PARAMETER_LAYOUTS) or len(names) != len(set(names)):
        return None, ("registry", len(names), len(ORIGINAL_PARAMETER_LAYOUTS))
    functions = []
    for name in names:
        function = getattr(regressions, name, None)
        if getattr(function, "__name__", None) != name:
            return None, ("missing", name)
        functions.append(function)
    return tuple(functions), None


def _relabel_parametrize(function, new_id):
    """Copy one original and change only its first explicit parameter id.

    Argument values stay on the copy. The function object that the module
    binds is not mutated, so the next collection still sees the recorded labels.
    """
    mark = _parametrize_marks(function)[0]
    names, params = mark.args[0], mark.args[1]
    first = params[0]
    updated = [pytest.param(*first.values, id=new_id, marks=tuple(getattr(first, "marks", ()) or ()))]
    updated.extend(params[1:])
    clone = types.FunctionType(function.__code__, function.__globals__, function.__name__,
                               function.__defaults__, function.__closure__)
    clone.__kwdefaults__ = getattr(function, "__kwdefaults__", None)
    annotations = getattr(function, "__annotations__", None)
    clone.__annotations__ = dict(annotations) if annotations else {}
    clone.__module__ = function.__module__
    clone.__qualname__ = function.__qualname__
    return pytest.mark.parametrize(names, tuple(updated))(clone)


def test_original_parameters_use_shared_rows_and_stable_case_ids():
    functions = {qualname.rsplit(".", 1)[-1] for _case_id, qualname, arguments in CORPUS_CASES
                 if arguments and qualname.startswith("tests.unit.core.test_primitives.")}
    assert set(ORIGINAL_PARAMETER_LAYOUTS) == functions
    assert len(functions) == 38
    for name in functions:
        mark = original_parameters(name)
        names, parameters = mark.args
        rows = [row for row in CORPUS_CASES if row[1] == "tests.unit.core.test_primitives." + name]
        assert len(parameters) == len(rows)
        function = _function_map()["tests.unit.core.test_primitives." + name]
        actual_rows, errors = original_call_cases((function,))
        assert errors == ()
        assert actual_rows == tuple(rows)
        for parameter, (_case_id, _qualname, arguments) in zip(parameters, rows):
            assert dict(zip(names, parameter.values)) == dict(arguments)

    name = "test_display_attribution_covers_shared_rule_families"
    substituted = _substitute_aws_row(CORPUS_CASES)
    mark = original_parameters(name, substituted)
    assert dict(zip(mark.args[0], mark.args[1][0].values)) == dict(
        next(arguments for case_id, _qualname, arguments in substituted if case_id == _aws_case_id()))
    assert shared_table_errors(CORPUS_CASES, substituted) == (("digest", _aws_case_id()),)


def test_original_parameters_reject_missing_duplicate_and_reordered_ids_then_retry_in_parallel():
    name = "test_display_attribution_covers_shared_rule_families"
    rows = tuple(row for row in CORPUS_CASES if row[1] == "tests.unit.core.test_primitives." + name)
    candidates = (rows[:-1], (rows[0],) + rows, (rows[1], rows[0]) + rows[2:],
                  (("nfa-wrong-0", rows[0][1], rows[0][2]),) + rows[1:])
    for candidate in candidates:
        with pytest.raises(ValueError, match="^shared display case ids do not match layout$"):
            original_parameters(name, candidate)
    with pytest.raises(ValueError, match="^unknown shared display function$"):
        original_parameters("missing")
    def arguments(marker):
        return marker.args[0], tuple(parameter.values for parameter in marker.args[1])

    expected = arguments(original_parameters(name))
    with ThreadPoolExecutor(max_workers=3) as pool:
        actual = list(pool.map(original_parameters, [name] * 6, timeout=10))
    assert [arguments(mark) for mark in actual] == [expected] * 6
    assert arguments(original_parameters(name)) == expected
    assert corpus_case_errors(CORPUS_CASES, ROUND1_CASE_BASELINE, UNEDITED_CORPUS_FLOOR) == ()


def _assert_no_collection_text(capsys):
    """Node ids and import failures stay off both streams."""
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_original_node_ids_match_the_pre686_baseline(tmp_path, capsys):
    # Argument parity still holds, and the collected selectors match the
    # pre-rewire originals per function and in order.
    originals, errors = original_call_cases()
    assert errors == ()
    assert shared_table_errors(CORPUS_CASES, originals) == ()
    functions, bind_error = bound_original_functions()
    assert bind_error is None
    collected, error = collect_original_node_ids(tmp_path / "originals", functions)
    assert error is None
    assert node_id_errors(collected, PRE686_NODE_BASELINE) == ()
    _assert_no_collection_text(capsys)


def test_original_collected_identity_rejects_wrong_label_then_retries(tmp_path, capsys):
    name = "test_display_escape_boundaries_mask_secrets_on_every_surface"
    function = getattr(regressions, name)
    clone = _relabel_parametrize(function, "relabelled")
    qualname = function.__module__ + "." + name
    rows = tuple(row for row in CORPUS_CASES if row[1] == qualname)
    actual, errors = original_call_cases((clone,))
    assert errors == ()
    # Values and ordinal ids still match. Only the pytest selector changed.
    assert shared_table_errors(rows, actual) == ()
    baseline_row = next(row for row in PRE686_NODE_BASELINE if row[0] == name)
    collected, error = collect_original_node_ids(tmp_path / "relabel", (clone,))
    assert error is None
    assert node_id_errors(collected, (baseline_row,)) == (("digest", name),)
    restored, error = collect_original_node_ids(tmp_path / "retry", (function,))
    assert error is None
    assert node_id_errors(restored, (baseline_row,)) == ()
    assert getattr(regressions, name) is function
    _assert_no_collection_text(capsys)


def test_original_node_ids_reject_singleton_autouse_fixture_label_then_retry(tmp_path, capsys):
    # One autouse fixture value renames every real selector. Argument parity
    # still holds. The guard must fail, then accept the unlabelled module.
    functions, bind_error = bound_original_functions()
    assert bind_error is None
    originals, errors = original_call_cases()
    assert errors == ()
    assert shared_table_errors(CORPUS_CASES, originals) == ()
    labelled, error = collect_original_node_ids(
        tmp_path / "fixture-label", functions, fixture_label="isolated-home")
    assert error is None
    mismatches = node_id_errors(labelled, PRE686_NODE_BASELINE)
    assert mismatches == tuple(("digest", name) for name, _count, _digest in PRE686_NODE_BASELINE)
    restored, error = collect_original_node_ids(tmp_path / "retry", functions)
    assert error is None
    assert node_id_errors(restored, PRE686_NODE_BASELINE) == ()
    assert collect_original_node_ids(
        tmp_path / "multiline", functions, fixture_label="isolated\nhome") == (None, ("node-id",))
    _assert_no_collection_text(capsys)


def test_original_node_ids_reject_post_yield_hookwrapper_relabel_then_retry(tmp_path, capsys):
    # A hookwrapper that edits node ids after yield renames the final selectors.
    # Argument parity still holds. The guard must fail, then accept a retry.
    functions, bind_error = bound_original_functions()
    assert bind_error is None
    originals, errors = original_call_cases()
    assert errors == ()
    assert shared_table_errors(CORPUS_CASES, originals) == ()
    labelled, error = collect_original_node_ids(
        tmp_path / "post-yield", functions, post_yield_relabel=True)
    assert error is None
    mismatches = node_id_errors(labelled, PRE686_NODE_BASELINE)
    assert mismatches == tuple(("digest", name) for name, _count, _digest in PRE686_NODE_BASELINE)
    restored, error = collect_original_node_ids(tmp_path / "retry", functions)
    assert error is None
    assert node_id_errors(restored, PRE686_NODE_BASELINE) == ()
    _assert_no_collection_text(capsys)


def test_original_node_ids_reject_module_collection_reorder_then_retry(tmp_path, capsys):
    functions, bind_error = bound_original_functions()
    assert bind_error is None
    functions = functions[:2]
    baseline = PRE686_NODE_BASELINE[:2]
    first, second = (function.__name__ for function in functions)

    class ReorderModuleCollection:
        @pytest.hookimpl(hookwrapper=True)
        def pytest_make_collect_report(self, collector):
            outcome = yield
            if not isinstance(collector, pytest.Module) or collector.path.name != "test_primitives.py":
                return
            # Change the module's child order before pytest matches CLI selectors.
            report = outcome.get_result()
            rank = {second: 0, first: 1}
            report.result.sort(key=lambda item: rank.get(_item_function_name(item), 2))

    changed, error = collect_original_node_ids(
        tmp_path / "reordered", functions, collection_plugin=ReorderModuleCollection())
    original, clean_error = collect_original_node_ids(tmp_path / "clean", functions)

    assert error is None
    assert clean_error is None
    assert node_id_errors(original, baseline) == ()
    assert node_id_errors(changed, baseline) == (("function", first), ("function", second))
    assert node_id_errors(changed, baseline[::-1]) == ()
    restored, error = collect_original_node_ids(tmp_path / "retry", functions)
    assert error is None
    assert node_id_errors(restored, baseline) == ()
    _assert_no_collection_text(capsys)


def test_node_id_guard_retries_after_rejection_and_concurrent_callers_agree(tmp_path, capsys):
    functions, bind_error = bound_original_functions()
    assert bind_error is None
    collected, error = collect_original_node_ids(tmp_path / "originals", functions)
    assert error is None
    assert node_id_errors(collected, PRE686_NODE_BASELINE) == ()
    saved = PRE686_NODE_BASELINE
    name, tails = collected[0]
    changed = ((name, tails[:-1] + (tails[-1] + "-x",)),) + collected[1:]
    short = ((name, tails[:-1]),) + collected[1:]

    def check(candidate):
        return node_id_errors(candidate, saved)

    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(check, [collected, changed, short] * 2, timeout=10))
    assert results[0::3] == [()] * 2
    assert results[1::3] == [(("digest", name),)] * 2
    assert results[2::3] == [(("count", name),)] * 2
    assert check(collected) == ()
    assert check(collected[:-1]) == (("registry", len(collected) - 1, len(saved)),)
    swapped = (collected[1], collected[0]) + collected[2:]
    assert any(item[0] == "function" for item in check(swapped))
    assert saved is PRE686_NODE_BASELINE
    _assert_no_collection_text(capsys)


def test_original_node_collection_refuses_limit_and_import_failure_then_retries(tmp_path, capsys):
    name = "test_display_attribution_preserves_ordinary_left_boundary"
    function = getattr(regressions, name)
    row = next(item for item in PRE686_NODE_BASELINE if item[0] == name)
    other_name = "test_display_escape_boundaries_mask_secrets_on_every_surface"
    other = getattr(regressions, other_name)
    other_row = next(item for item in PRE686_NODE_BASELINE if item[0] == other_name)
    # Same basename on purpose. The retry must collect the live module, not a
    # module cached from the earlier directory.
    primed, error = collect_original_node_ids(tmp_path / "earlier" / "retry", (other,))
    assert error is None
    assert node_id_errors(primed, (other_row,)) == ()
    limited, error = collect_original_node_ids(tmp_path / "limit", (function,), limit=1)
    assert limited is None and error == ("limit",)
    broken, error = collect_original_node_ids(
        tmp_path / "broken", (), source="import does_not_exist_for_original_node_ids\n", limit=8)
    assert broken is None and error[0] == "collection" and error[1] != 0
    assert all(isinstance(part, (str, int)) and "does_not_exist_for_original_node_ids" not in str(part) for part in error)
    restored, error = collect_original_node_ids(tmp_path / "later" / "retry", (function,))
    assert error is None
    assert node_id_errors(restored, (row,)) == ()
    assert collect_original_node_ids(tmp_path / "bad-limit", (function,), limit=False) == (None, ("limit",))
    _assert_no_collection_text(capsys)


def test_original_reader_uses_parametrize_marks():
    @pytest.mark.parametrize("value", ["one", "two"])
    @pytest.mark.parametrize("surface", ["sanitize"])
    def sample(value, surface):
        pass

    qualname = sample.__module__ + "." + sample.__name__
    originals, errors = original_call_cases((sample,))
    assert errors == ()
    expected = (
        ("nfa-sample-0", qualname, (("surface", "sanitize"), ("value", "one"))),
        ("nfa-sample-1", qualname, (("surface", "sanitize"), ("value", "two"))),
    )
    assert originals == expected
    copied = (expected[1][0], expected[1][1], expected[0][2])
    assert shared_table_errors(expected, (expected[0], copied)) == (("digest", "nfa-sample-1"),)

    @pytest.mark.parametrize("surface", [])
    def empty(surface):
        pass

    _rows, empty_errors = original_call_cases((empty,))
    assert empty_errors == (("empty-parametrize", empty.__module__ + "." + empty.__name__),)

    @pytest.mark.parametrize("left, right", ["only-one"])
    def bad_width(left, right):
        pass

    _rows, width_errors = original_call_cases((bad_width,))
    assert width_errors == (("parametrize-width", bad_width.__module__ + "." + bad_width.__name__),)


def test_original_divergence_fails_in_both_directions():
    # Exercise the guard independently of future changes to the original tests.
    originals = CORPUS_CASES
    aws_id = _aws_case_id()
    assert shared_table_errors(CORPUS_CASES, _substitute_aws_row(originals)) == (("digest", aws_id),)
    removed = tuple(row for row in originals if row[0] != aws_id)
    assert shared_table_errors(CORPUS_CASES, removed) == (("ids", (), (aws_id,)),)
    added = originals + (("nfa-synthetic-added", originals[0][1], originals[0][2]),)
    assert shared_table_errors(CORPUS_CASES, added) == (("ids", ("nfa-synthetic-added",), ()),)
    table_extra = CORPUS_CASES + (("nfa-synthetic-table", originals[0][1], originals[0][2]),)
    assert shared_table_errors(table_extra, originals) == (("ids", (), ("nfa-synthetic-table",)),)
    swapped = (originals[1], originals[0]) + originals[2:]
    assert shared_table_errors(CORPUS_CASES, swapped) == (("order",),)
    renamed = ((originals[0][0], originals[0][1] + ".other", originals[0][2]),) + originals[1:]
    assert shared_table_errors(CORPUS_CASES, renamed) == (("function", originals[0][0]),)
    duplicated = shared_table_errors(CORPUS_CASES, (originals[0],) + originals)
    assert ("duplicate-id", "original", (originals[0][0],)) in duplicated
    assert any(item[0] == "order" for item in duplicated)
    table_aws = tuple(row for row in CORPUS_CASES if row[0] == aws_id)
    bad = ((aws_id, table_aws[0][1], (("surface", object()),)),)
    assert shared_table_errors(table_aws, bad) == (("digest-type", aws_id),)
    assert shared_table_errors(CORPUS_CASES, originals) == ()


def test_original_guard_retries_and_concurrent_callers_agree():
    originals = CORPUS_CASES
    substituted = _substitute_aws_row(originals)
    saved_table = CORPUS_CASES

    def check(candidate):
        return shared_table_errors(saved_table, candidate)

    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(check, [originals, substituted] * 3))
    assert results[0::2] == [()] * 3
    assert results[1::2] == [(("digest", _aws_case_id()),)] * 3
    assert check(originals) == ()
    assert saved_table is CORPUS_CASES
    assert CORPUS_CASES == originals


def test_case_guard_retries_after_rejection_and_concurrent_callers_agree():
    substituted = _substitute_aws_row(CORPUS_CASES)
    saved_baseline = ROUND1_CASE_BASELINE
    saved_cases = CORPUS_CASES

    def check(candidate):
        return corpus_case_errors(candidate, saved_baseline, UNEDITED_CORPUS_FLOOR)

    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(check, [saved_cases, substituted] * 3))
    assert results[0::2] == [()] * 3
    assert results[1::2] == [(("digest", _aws_case_id()),)] * 3
    assert check(saved_cases) == ()
    assert saved_baseline is ROUND1_CASE_BASELINE
    assert saved_cases is CORPUS_CASES


def test_nfa_wrapper_compares_acceptance_and_returns_the_nfa_result():
    calls = []

    def original(grammar, text, runs, charge, **kwargs):
        calls.append((kwargs.get("memoize", True), kwargs.get("start_at"), charge(1)))
        return "accepted"

    def budget(amount):
        return ("budget", amount)

    assert nfa_checked(original)("g", "text", (), budget, start_at=2) == "accepted"
    assert calls == [(False, 2, True), (True, 2, True), (False, 2, ("budget", 1))]


def test_nfa_wrapper_refuses_disagreement_before_the_budget_call():
    calls = []

    def original(grammar, text, runs, charge, **kwargs):
        calls.append(kwargs.get("memoize", True))
        return bool(kwargs.get("memoize", True))

    def budget(amount):
        calls.append("budget")
        return True

    with pytest.raises(AssertionError):
        nfa_checked(original)("g", "text", (), budget)
    assert calls == [False, True]


def test_failed_compile_retries_and_concurrent_callers_share_one_graph(monkeypatch):
    saved = _REAL_TABLES[0]
    lock = _TABLES_LOCK
    callers = 6
    overlap = threading.Barrier(callers, timeout=5)
    attempts = []

    class ObservedLock:
        def __enter__(self):
            if not lock.acquire(blocking=False):
                # A caller that found the cache lock held has reached the lookup.
                overlap.wait()
                assert lock.acquire(timeout=5), "cache lock did not release"

        def __exit__(self, *exc):
            lock.release()

    def flaky():
        if len(attempts) < 2:
            attempts.append(None)
            raise RuntimeError("attribution graph compile failed")
        # Each caller meets here either inside the compiler or at the held lock.
        overlap.wait()
        graph = object()
        attempts.append(graph)
        return ("width", graph, "matcher")

    monkeypatch.setattr("tests.unit.core.test_display_attribution_dense._TABLES_LOCK", ObservedLock())
    monkeypatch.setattr("aegis_core.primitives._display_attribution_tables", flaky)
    _REAL_TABLES[0] = None
    try:
        for _ in range(2):
            with pytest.raises(RuntimeError, match="attribution graph compile failed"):
                real_attribution_tables()
            assert _REAL_TABLES[0] is None
        with ThreadPoolExecutor(max_workers=callers) as pool:
            results = list(pool.map(lambda _: real_attribution_tables(), range(callers), timeout=15))
        assert len(attempts) == 3, "expected one successful compile after two failures"
        assert results == [("width", attempts[-1], "matcher")] * callers
        assert all(result is results[0] for result in results)
    finally:
        _REAL_TABLES[0] = saved


def test_second_replay_does_not_recompile(monkeypatch):
    saved = _REAL_TABLES[0]
    _REAL_TABLES[0] = None
    compiled = []
    real_compile = attribution.compile_possible

    def counting(patterns, *, carried_patterns=()):
        compiled.append(1)
        return real_compile(patterns, carried_patterns=carried_patterns)

    primitives._display_attribution_tables.cache_clear()
    monkeypatch.setattr("aegis_core.display_attribution.compile_possible", counting)
    try:
        first = real_attribution_tables()
        checked = nfa_checked(attribution.may_match_visible)
        assert install_nfa_replay(monkeypatch, checked) is first[1]
        assert primitives._display_attribution_tables()[2] is checked
        assert install_nfa_replay(monkeypatch, checked) is first[1]
        assert compiled == [1]
    finally:
        _REAL_TABLES[0] = saved


@pytest.mark.parametrize("function,arguments", UNEDITED_CORPUS)
def test_unedited_regression_corpus_memo_parity(function, arguments, monkeypatch):
    # Each original assertion still checks the complete public display output.
    # At every graph search compare cached and uncached acceptance without
    # exhaustion, then run that assertion on the NFA result. The graph is the
    # one compile shared by every case.
    install_nfa_replay(monkeypatch, nfa_checked(attribution.may_match_visible))
    function(**arguments)

def instrumented_cases():
    """Inputs from the fixture-based regressions; their instrumentation stays in the original file."""
    key = "AK" + "IA" + "A" * 16
    candidate = "\x1b[" + key[:4] + "\x1b[31m" + key[4:]
    yield "before\x1b]title\x07" + candidate + "\x1b]title\x07after"
    for count in (128, 1024, 8192):
        yield "gh" + "p_" + "\x1b[a" * count + "!"
    for value in ("plain", "\r\x00safe", "before\x1b]title", "\x9b31mplain",
                  "before\x1b]title\x07after", "\t\n"):
        yield value
    part = "z" * (2 * primitives._display_attribution_width() + 77)
    yield part + "\x1b[31m" + part + "\x1b[31m" + part
    for count in (5000, 50000):
        gap = "\x00" * count
        yield "\x1b[" + key[:1] + gap + key[1:4] + "\x1b[31m" + key[4:]
        yield "\x1b[" + key[:4] + gap + "\x1b[31m" + key[4:]
        yield "\x1b[" + key[:4] + "\x1b[31m" + gap + key[4:]
    prefix = "git" + "hub_pat_"
    yield prefix + "a" * 200 + "_" + prefix + "\x1b[b" + "b" * 99


@pytest.mark.parametrize("value", [pytest.param(value, id=f"case-{index}")
                                    for index, value in enumerate(instrumented_cases())])
def test_instrumented_regression_inputs_have_identical_output(value, monkeypatch):
    expected = primitives.sanitize_display(value, max_len=None)
    monkeypatch.setattr("aegis_core.display_attribution._DFA_STATE_LIMIT", 0)
    assert primitives.sanitize_display(value, max_len=None) == expected
