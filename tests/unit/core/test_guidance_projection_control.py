"""D-al equivalence and output parity for guidance's ASCII prefilter."""
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
import unicodedata

import pytest

from aegis_core import guidance_projection as projection
from aegis_core.skills.slots import SlotRegistry
from aegis_core.yaml_engine.frontmatter import split_frontmatter


def _category_definition(text, start=0, end=None):
    return any(unicodedata.category(text[index]) in {"Cf", "Cs"}
               or (unicodedata.category(text[index]) == "Cc" and text[index] not in "\t\n\r")
               for index in range(start, len(text) if end is None else end))


def test_d_al_matches_every_unicode_code_point_with_and_without_bounds():
    for point in range(0x110000):
        char = chr(point)
        expected = unicodedata.category(char) in {"Cf", "Cs"} or (
            unicodedata.category(char) == "Cc" and char not in "\t\n\r")
        assert projection.contains_control_characters(char) == expected, point
        assert projection.contains_control_characters("a" + char + "z", 1, 2) == expected, point


@pytest.mark.parametrize("text", ["", "plain", "\x00abc\u200d", "\ud800\t\n\r", "a\u2028\u2029z"])
def test_bounds_preserve_index_order_empty_ranges_and_reached_index_errors(text):
    for start in range(-len(text) - 2, len(text) + 3):
        for end in [None] + list(range(-len(text) - 2, len(text) + 3)):
            try:
                expected = _category_definition(text, start, end)
            except IndexError:
                with pytest.raises(IndexError, match="^string index out of range$"):
                    projection.contains_control_characters(text, start, end)
            else:
                assert projection.contains_control_characters(text, start, end) == expected


def test_ascii_does_not_enter_unicode_category_and_candidates_are_checked_once(monkeypatch):
    calls = []

    def category(char):
        calls.append(char)
        return unicodedata.category(char)

    monkeypatch.setattr(projection, "unicodedata", SimpleNamespace(category=category))
    ascii_text = "\t\n\r" + "".join(chr(point) for point in range(32, 127))
    assert not projection.contains_control_characters(ascii_text)
    assert calls == []
    assert projection.contains_control_characters(ascii_text + "\u00a0\U0001f600\x7f\u200d")
    assert calls == ["\u00a0", "\U0001f600", "\x7f"]


@pytest.mark.parametrize("char", ["A", "\t", "\n", "\r", "\x00", "\x7f", "\x85", "\ufeff",
                                  "\u200d", "\ud800", "\u2028", "\u2029", "\u00a0", "\ue000", "\U0001f600"])
def test_public_projection_callers_match_category_definition_on_retry_and_concurrent_reads(char, monkeypatch):
    candidate = projection.contains_control_characters
    body = "## Do\nKeep " + char + " safe."
    raw = ("---\nid: parity\n---\n" + body).encode("utf-8", "surrogatepass")
    prefix = "## Do\nKeep " + char + " safe."
    registry = SlotRegistry({"CUSTOM": char})
    calls = [
        lambda: projection.raw_rule_text(raw, split_frontmatter),
        lambda: projection.project_text(body),
        lambda: projection.project_field([body]),
        lambda: projection.project_text("Keep ${SLOT.CUSTOM} safe.", registry),
        lambda: projection.normalize_layout(char),
        lambda: projection.redact_clean_text(char),
        lambda: projection.assembled_text(char),
        lambda: projection.project_identifier(char),
        lambda: projection.project_diagnostic(char),
        lambda: projection.project_detail(body),
        lambda: projection.detail_instruction_visible(body, prefix),
        lambda: projection.project_text("Keep safe.\n## Evidence\n" + char),
        lambda: projection.project_field(["Keep safe.", "## Evidence", char]),
    ]

    def results(_=None):
        outputs = []
        for call in calls:
            try:
                outputs.append(call())
            except projection.GuidanceProjectionError as error:
                outputs.append((type(error), error.code, str(error)))
        return outputs

    monkeypatch.setattr(projection, "contains_control_characters", _category_definition)
    expected = results()
    monkeypatch.setattr(projection, "contains_control_characters", candidate)
    assert results() == results() == expected
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(results, range(3), timeout=15)) == [expected] * 3
    assert expected[-2:] == ["Keep safe.", ["Keep safe."]]


@pytest.mark.parametrize("escape", [r"t", r"x85", r"u200d", r"U0000feff", r"N{ZERO WIDTH SPACE}"])
@pytest.mark.parametrize("count", [1, 2, 3, 4, 5, 6])
def test_diagnostic_escape_parity_and_idempotence(escape, count):
    slashes = "\\" * count
    value = "before" + slashes + escape + "after"
    expected = "before" + ("\\" * (count - 1) + " " if count % 2 else slashes + escape) + "after"
    assert projection.project_diagnostic(value) == expected
    assert projection.project_diagnostic(expected) == expected
    assert projection.project_diagnostic(value, escaped=False) == value


def test_diagnostics_do_not_recheck_canonical_text_with_served_control_predicate(monkeypatch):
    def unexpected(*args, **kwargs):
        pytest.fail("canonical diagnostics have already removed all served control candidates")

    monkeypatch.setattr(projection, "contains_control_characters", unexpected)
    assert projection.project_diagnostic(" a\u200d\\t\ud800 b ") == "a b"


@pytest.mark.parametrize("escaped", [True, False])
def test_diagnostic_bounds_refusals_redact_before_clip_and_retry(escaped):
    limit = projection.MAX_GUIDANCE_CHARS
    assert projection.project_diagnostic("x" * limit, escaped=escaped) == "x" * 1021 + "..."
    assert projection.project_diagnostic("x" * (limit + 1), escaped=escaped) == "guidance_projection_limit"
    assert projection.project_diagnostic(None, escaped=escaped) == "guidance_projection_invalid_field"
    secret = "S" * 40
    source = "x" * 1000 + " Bearer\t" + secret
    shown = projection.project_diagnostic(source, escaped=escaped)
    assert shown == "x" * 1000 + " Bearer REDACTED"
    assert projection.project_diagnostic(shown, escaped=escaped) == shown
    assert projection.project_diagnostic("plain", escaped=escaped) == "plain"


@pytest.mark.parametrize("value", [r"\N{unknown}", r"\N{}", r"\N{SPACE", r"\N{ZERO\tWIDTH SPACE}"])
def test_diagnostic_malformed_escapes_refuse_without_echo_and_retry_concurrently(value):
    def refusing_then_retry(_):
        assert projection.project_diagnostic(value) == "guidance_projection_invalid_field"
        return projection.project_diagnostic("plain")

    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(refusing_then_retry, range(6), timeout=15)) == ["plain"] * 6


@pytest.mark.parametrize("passes", [1, 2, 18, 31, 32, 33])
def test_error_name_fixed_point_has_a_32_pass_budget(passes, monkeypatch):
    source = "plain" if passes == 1 else "ghp_" + "A" * (247 * (passes - 2) + 20)
    original = projection.project_identifier
    calls = []

    def tracked(value):
        calls.append(value)
        return original(value)

    monkeypatch.setattr(projection, "project_identifier", tracked)
    expected = "plain" if passes == 1 else (
        "ghp_REDACTED" if passes <= 32 else "guidance_projection_invalid_field")
    assert projection.project_error_name(source) == expected
    assert len(calls) == min(passes, 32)
    assert projection.project_error_name(expected) == expected
    assert projection.project_error_name("retry") == "retry"


@pytest.mark.parametrize("value", [None, "", "name\nsecond", "name\rsecond", "name\u200d"])
def test_error_name_invalid_fields_refuse_without_echo_then_retry(value):
    assert projection.project_error_name(value) == "guidance_projection_invalid_field"
    assert projection.project_error_name("retry") == "retry"


def test_error_name_character_cap_precedes_content_checks(monkeypatch):
    source = "a" * projection.MAX_GUIDANCE_CHARS
    assert projection.project_error_name(source) == source

    def unexpected(value):
        pytest.fail("oversized names must refuse before content checks")

    monkeypatch.setattr(projection, "contains_control_characters", unexpected)
    with pytest.raises(projection.GuidanceProjectionError, match="^guidance_projection_limit$") as caught:
        projection.project_error_name(source + "a")
    assert caught.value.code == "guidance_projection_limit"


def test_error_name_budget_is_per_call_on_concurrent_refusal_and_retry():
    source = "ghp_" + "A" * (247 * 31 + 20)

    def refusing_then_retry(_):
        assert projection.project_error_name(source) == "guidance_projection_invalid_field"
        assert projection.project_error_name("ghp_" + "A" * 1024) == "ghp_REDACTED"
        return projection.project_error_name("retry")

    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(refusing_then_retry, range(6), timeout=15)) == ["retry"] * 6
