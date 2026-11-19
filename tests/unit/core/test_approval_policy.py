"""Branch approval policy through committed Git objects and the public CI gate."""
import ast
from concurrent.futures import ThreadPoolExecutor
import difflib
import json
from pathlib import Path
import random
import string
import sys
from string import Formatter
from threading import Barrier
from types import SimpleNamespace

import pytest

from aegis_core import approval_policy, diagnostic_messages, gitsafe, human_gate, rule_integrity
from aegis_core import redaction as display_redaction
from aegis_cli import cli
from tests import helpers_humangate as hg

MAP = {"main": "signature", "develop": "review", "release/**": "review", "*": "none"}


@pytest.mark.parametrize("limit", [0, 1, 2, 3, 4, 11, 20, 40, 120, 300, 393, 398, 400])
@pytest.mark.parametrize("ellipsis", [False, True])
def test_finished_text_clipping_preserves_atomic_units_and_template_literals(limit, ellipsis):
    for token in (r"\x26", r"\u202e", r"\U0001f600", "[REDACTED_IP]", r"\\", r"\x3"):
        value = "fixed (header); 'value': " + token * 110
        shown = approval_policy.clip_rendered_text(value, limit, ellipsis=ellipsis)
        assert len(shown) <= limit
        assert approval_policy.clip_rendered_text(shown, limit, ellipsis=ellipsis) == shown
        if limit >= len(value):
            assert shown == value
        if token.startswith("["):
            assert shown.count("[") == shown.count("]")
    value = "fixed (header); 'value': " + r"\x26" * 100
    shown = approval_policy.clip_rendered_text(value, 400)
    assert shown.startswith("fixed (header); 'value': ")
    assert not any(unit == "\\" and not escaped for unit, escaped in display_redaction._escape_units(shown))


def test_finished_text_refuses_oversized_input_before_sanitization(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("finished text reached sanitization")

    monkeypatch.setattr(diagnostic_messages, "primitives", SimpleNamespace(sanitize_display=forbidden))
    assert approval_policy.clip_rendered_text("a" * 81921) == "diagnostic_omitted_too_large"
    with pytest.raises(AssertionError, match="finished text reached sanitization"):
        approval_policy.clip_rendered_text("ordinary")


@pytest.mark.parametrize("ellipsis", [False, True])
def test_finished_text_redacts_new_matches_at_the_wire_cut(ellipsis):
    for padding in range(370, 405):
        rendered = approval_policy.guidance_value("a" * padding + " 1.2.3.4x tail", 8192, prose=True)
        shown = approval_policy.clip_rendered_text("prefix: " + rendered, 400, ellipsis=ellipsis)
        assert len(shown) <= 400
        assert "1.2.3.4" not in shown or "1.2.3.4x" in shown
        assert approval_policy.guidance_value(shown, 8192, prose=True) == shown.rstrip()
        assert approval_policy.clip_rendered_text(shown, 400, ellipsis=ellipsis) == shown


def test_finished_text_redaction_has_a_fail_closed_pass_bound(monkeypatch):
    calls = [0]

    def changing(units):
        calls[0] += 1
        return list(display_redaction._escape_units("a" if calls[0] % 2 else "b"))

    monkeypatch.setattr(display_redaction, "_redact_units", changing)
    assert approval_policy.clip_rendered_text("a" * 800) == "diagnostic_omitted_too_large"
    assert 0 < calls[0] <= 16


def _within_redaction_budget(action, size=400, *, call_steps=False):
    """Bound actual work; generated cases count Python/regex calls, direct cases lines."""
    from aegis_core import redaction

    tracked = {diagnostic_messages.__file__, approval_policy.__file__, redaction.__file__, __file__}
    steps = [0]
    previous = sys.getprofile() if call_steps else sys.gettrace()

    def count(frame, event, arg):
        if (event in ("call", "c_call") if call_steps else event == "line") and frame.f_code.co_filename in tracked:
            steps[0] += 1
            assert steps[0] <= (160 * size + 5000 if call_steps else 500 * size + 20000), "redaction exceeded its step budget"
        return count

    try:
        (sys.setprofile if call_steps else sys.settrace)(count)
        return action()
    finally:
        (sys.setprofile if call_steps else sys.settrace)(previous)
        assert steps[0] > 0


@pytest.mark.parametrize("value", ["a" * 391 + " /home/alice", "a" * 392 + " /home/a",
    "a" * 390 + " /Users/alice", "a" * 388 + " C:\\Users\\alice",
    "a" * 373 + " /home/alice token=secret12345"])
@pytest.mark.parametrize("prose", [False, True], ids=["strict", "prose"])
def test_home_masks_terminate_whole_and_stable(value, prose):
    shown = _within_redaction_budget(lambda: approval_policy.guidance_value(value, prose=prose))
    assert approval_policy.guidance_value(shown, prose=prose) == shown
    assert "alice" not in shown and "secret12345" not in shown
    assert not any(shown.endswith(part) for part in ("~", "~u", "~us", "~use"))


@pytest.mark.parametrize("receipt", [False, True])
def test_nonconverging_redactor_has_a_hard_fail_closed_bound(monkeypatch, receipt):
    calls = [0]

    def changing(units):
        calls[0] += 1
        return list(display_redaction._escape_units("a" if calls[0] % 2 else "b"))

    monkeypatch.setattr(display_redaction, "_redact_units", changing)
    shown = _within_redaction_budget(lambda: approval_policy.receipt_value("source") if receipt else
                                    approval_policy.guidance_value("source", prose=True))
    assert shown == ("[diagnostic omitted: too_large]" if receipt else "diagnostic_omitted_too_large")
    assert calls[0] <= 17


@pytest.mark.parametrize("spelling", ["x", "u", "U"])
@pytest.mark.parametrize("prefix,secret,suffix,expected", [
    ("token=", "secret]", "", "token=[REDACTED]"),
    ("token=", "[secret", "", "token=[REDACTED]"),
    ("/home/", "petr", "/file", "/home/~user/file"),
    ("/Users/", "~secret", "/file", "/Users/~user/file"),
    ("https://user:", "secret]", "@host", "https://user:[REDACTED]@host"),
])
def test_matched_secret_units_are_replaced_even_when_they_equal_mask_edges(spelling, prefix, secret, suffix, expected):
    edge = 0 if secret[0] in "[~" else len(secret) - 1
    encoded = "\\" + spelling + format(ord(secret[edge]), {"x": "02x", "u": "04x", "U": "08x"}[spelling])
    value = prefix + secret[:edge] + encoded + secret[edge + 1:] + suffix
    shown = approval_policy.guidance_value(value, prose=True)
    assert shown == expected
    assert encoded not in shown
    assert approval_policy.guidance_value(shown, prose=True) == shown


@pytest.mark.parametrize("identifier,value", [(False, "aaaa 1.2.3.4x"), (True, "token=digest")])
@pytest.mark.parametrize("limit", range(8, 15))
def test_receipt_clipping_redacts_again_and_keeps_whole_masks(identifier, value, limit):
    shown = approval_policy.receipt_value(value, limit, identifier=identifier)
    assert approval_policy.receipt_value(shown, limit, identifier=identifier) == shown
    assert "1.2.3.4" not in shown or shown.endswith("1.2.3.4x")
    assert "digest" not in shown or shown == value
    assert shown.count("[") == shown.count("]")
    assert not any(shown.endswith("REDACTED"[:cut]) for cut in range(1, 8))


@pytest.mark.parametrize("identifier", [False, True])
@pytest.mark.parametrize("fragment", [r"\x3", r"\u003", r"\U0000003", r"\\x3", r"\\u003", r"\\U0000003"])
def test_receipt_splicing_cannot_complete_a_partial_escape(fragment, identifier):
    prefix, mask = "a" * 98 + " token" + fragment, "AKIA_REDACTED"
    limit = len(prefix) + len(mask)
    shown = _within_redaction_budget(lambda: approval_policy.receipt_value(prefix + ".." + mask, limit,
                                                                         identifier=identifier))
    assert approval_policy.receipt_value(shown, limit, identifier=identifier) == shown
    assert mask in shown and shown.count("[") == shown.count("]")


@pytest.mark.parametrize("identifier", [False, True])
def test_the_exact_argon_escape_splice_is_a_fixpoint(identifier):
    value = "a" * 98 + r" token\x3..AKIA_REDACTED"
    shown = approval_policy.receipt_value(value, identifier=identifier)
    assert approval_policy.receipt_value(shown, identifier=identifier) == shown
    value = r"token\x3..AKIA_REDACTED"
    shown = approval_policy.receipt_value(value, 21, identifier=identifier)
    assert approval_policy.receipt_value(shown, 21, identifier=identifier) == shown


@pytest.mark.parametrize("value", [r"\\", r"\q", r"\x3", r"\u003", r"\U0000003"])
@pytest.mark.parametrize("identifier", [False, True])
def test_receipts_keep_or_drop_each_literal_escape_form_whole_at_the_cut(value, identifier):
    for limit in range(1, len(value) + 1):
        shown = approval_policy.receipt_value(value + " tail", limit, identifier=identifier)
        assert shown == "" or shown.startswith(value) or shown.startswith(r"\x5c")
        assert approval_policy.receipt_value(shown, limit, identifier=identifier) == shown


@pytest.mark.parametrize("mask", ["[REDACTED_IP]", "[REDACTED_VCS_TOKEN]", "~user", "AKIA_REDACTED", "REDACTED"])
@pytest.mark.parametrize("spelling", ["raw", "x", "u", "U"])
@pytest.mark.parametrize("surface", ["strict", "prose", "receipt", "identifier"])
@pytest.mark.parametrize("limit", [40, 400])
def test_existing_masks_are_atomic_across_every_cut(mask, spelling, surface, limit):
    encoded = mask if spelling == "raw" else "".join("\\" + spelling + format(ord(char),
                    {"x": "02x", "u": "04x", "U": "08x"}[spelling]) for char in mask)

    def render(value, limit):
        if surface in ("receipt", "identifier"):
            return approval_policy.receipt_value(value, limit, identifier=surface == "identifier")
        return approval_policy.guidance_value(value, limit, prose=surface == "prose")

    # Place the cutoff before, at every interior position, and after the mask.
    for offset in range(-1, len(mask) + 2):
        prefix = "a" * (limit - 1 - offset) + " "
        value = prefix + encoded + " tail"
        shown = _within_redaction_budget(lambda: render(value, limit), len(value) + limit)
        decoded = "".join(chr(int(unit[2:], 16)) if escaped else unit
                          for unit, escaped in display_redaction._escape_units(shown))
        assert decoded in (prefix[:limit], prefix[:limit].rstrip()) or mask in decoded, (
            mask, spelling, surface, offset, decoded)
        if mask.startswith("[") or "[" in mask:
            assert decoded.count("[") == decoded.count("]")
        assert render(shown, limit) == shown


def test_existing_mask_too_large_for_the_limit_is_dropped_whole():
    for value in ("[REDACTED_IP]", r"\x5bREDACTED_IP\x5d", "~user"):
        assert approval_policy.guidance_value(value, 2, prose=True) == ""
        assert approval_policy.receipt_value(value, 2) == ""
        assert approval_policy.receipt_value(value, 2, identifier=True) == ""


@pytest.mark.parametrize("value", ["password is Bearer [REDACTED]", "token=Bearer [REDACTED]",
                                  "password is Bearer abcdefghijklmnop", "Authorization: Bearer " + "a1" * 10])
@pytest.mark.parametrize("limit", [2, 40, 400])
def test_redaction_masks_never_absorb_whitespace(value, limit):
    for prose in (False, True):
        shown = approval_policy.guidance_value("a" * (limit - 2) + " " + value, limit, prose=prose)
        assert "diagnostic_omitted" not in shown
        assert "  " not in shown
        assert approval_policy.guidance_value(shown, limit, prose=prose) == shown
    for identifier in (False, True):
        shown = approval_policy.receipt_value(value, limit, identifier=identifier)
        assert "diagnostic omitted" not in shown
        assert "  " not in shown
        assert approval_policy.receipt_value(shown, limit, identifier=identifier) == shown


@pytest.mark.parametrize("prose", [False, True])
@pytest.mark.parametrize("value", ["::none", "to ::none", "a:::b", "a::::b", r"a\x3a::b"])
def test_every_double_colon_is_inert_and_stable(value, prose):
    shown = approval_policy.guidance_value(value, prose=prose)
    assert "::" not in shown
    assert approval_policy.guidance_value(shown, prose=prose) == shown


@pytest.mark.parametrize("identifier", [False, True])
@pytest.mark.parametrize("limit", [0, 1, 2, 8, 29, 30, 40, 120, 400])
def test_oversized_receipt_fallback_is_bounded_and_stable_before_canonicalization(identifier, limit):
    def forbidden(*args, **kwargs):
        pytest.fail("oversized receipt reached canonicalization")

    for value in ("a" * 8193, "a" * 81921, r"\x61" * 8193):
        shown = approval_policy.receipt_value(value, limit, identifier=identifier, canonicalize=forbidden)
        assert len(shown) <= limit
        assert approval_policy.receipt_value(shown, limit, identifier=identifier) == shown


@pytest.mark.parametrize("value,expected", [("refs/remotes/upstream/main", "refs/remotes/upstream/main"),
    ("foo&bar", r"foo\x26bar"), ("o'$(id)", r"o\x27\x24\x28id\x29"), ("-flag", r"\x2dflag"),
    ("développement", r"d\xe9veloppement"), ("a`b;|>\"", r"a\x60b\x3b\x7c\x3e\x22"),
    ("foo\\x26bar", r"foo\x26bar"), ("a\x1b[31m&b", r"a\x26b"),
    ("\u202e\U0001f600", r"\u202e\U0001f600")])
def test_guidance_value_preserves_safe_tokens_and_hex_escapes_other_characters(value, expected):
    assert approval_policy.guidance_value(value) == expected


@pytest.mark.parametrize("prose", [False, True], ids=["strict", "prose"])
@pytest.mark.parametrize("value,expected", [(r"\x24", r"\x24"), (r"\x5c", r"\x5c"),
    ("\\", r"\x5c"), (r"\xG4", r"\x5cxG4"), (r"\x2", r"\x5cx2"), (r"\X24", r"\x5cX24")])
def test_guidance_preserves_only_complete_hex_escapes_and_escapes_lone_backslashes(value, expected, prose):
    assert approval_policy.guidance_value(value, prose=prose) == expected


@pytest.mark.parametrize("prose", [False, True], ids=["strict", "prose"])
@pytest.mark.parametrize("value,expected", [
    (r"\u202e", r"\u202e"), (r"\U000e0001", r"\U000e0001"),
    (r"\U0010ffff", r"\U0010ffff"), (r"\ud800", r"\ud800"),
    ("\u202e", r"\u202e"),
    (r"\u12", r"\x5cu12"), (r"\U00110000", r"\x5cU00110000"),
    (r"\uZZZZ", r"\x5cuZZZZ"), (r"\Uffffffff", r"\x5cUffffffff"),
    ("ending\\", r"ending\x5c"),
], ids=["literal-u", "literal-U", "maximum-U", "surrogate-u", "raw-format-character",
        "short-u", "out-of-range-U", "malformed-u", "maximum-invalid-U", "trailing-backslash"])
def test_guidance_unicode_escape_controls_are_inert_and_idempotent(value, expected, prose):
    shown = approval_policy.guidance_value(value, prose=prose)
    assert shown == expected
    assert approval_policy.guidance_value(shown, prose=prose) == shown


@pytest.mark.parametrize("prose", [False, True], ids=["strict", "prose"])
@pytest.mark.parametrize("alphabet", ["ascii", "unicode"])
def test_guidance_escape_is_idempotent_for_generated_values(prose, alphabet):
    from tests.unit.cli.test_check_ci_push import EXECUTION_MARKERS

    rng = random.Random(20261114)
    values = list(EXECUTION_MARKERS) + [r"\x24", "\\", r"\x00\xFF", "::warning::forged",
              "a" * 399 + " end", " " + r"\x24" + " ", "a" * 9000, ("'" * 4096), ("a;" * 4096)]
    if alphabet == "ascii":
        values += ["".join(rng.choice(string.printable) for _ in range(rng.randrange(0, 700))) for _ in range(200)]
    else:
        values += ["\u202e", "\U000e0001", "\ud800", "漢字 café"]
        values += ["".join(chr(rng.randrange(0x110000)) for _ in range(rng.randrange(0, 700))) for _ in range(200)]
    for limit in (40, 400, 4096):
        for value in values:
            once = approval_policy.guidance_value(value, limit, prose=prose)
            assert approval_policy.guidance_value(once, limit, prose=prose) == once


def test_guidance_value_redacts_after_canonicalization_before_truncating():
    token = "ghp_" + "a" * 36
    value = "x" * 380 + "/ghp_" + "a" * 10 + "\x1b[31m" + "a" * 26
    displayed = approval_policy.guidance_value(value)
    assert token not in displayed and "a" * 20 not in displayed
    assert "REDACTED" in displayed and displayed.isascii()
    assert approval_policy.guidance_value("a" * 401) == "a" * 400


@pytest.mark.parametrize("prose", [False, True], ids=["strict", "prose"])
def test_guidance_redacts_the_ip_exposed_by_truncation(prose):
    value = "a" * 392 + " 1.2.3.4x"
    shown = approval_policy.guidance_value(value, prose=prose)
    assert "1.2.3.4" not in shown
    assert approval_policy.guidance_value(shown, prose=prose) == shown


@pytest.mark.parametrize("prose", [False, True], ids=["strict", "prose"])
@pytest.mark.parametrize("limit", [40, 400, 4096])
def test_guidance_redaction_family_boundaries_remain_a_fixpoint(prose, limit):
    from tests.unit.cli.test_check_ci_push import REDACTION_BOUNDARIES

    for probe, boundary in REDACTION_BOUNDARIES.values():
        for delta in range(-2, 3):
            value = "a" * (limit - boundary - 1 + delta) + " " + probe
            shown = approval_policy.guidance_value(value, limit, prose=prose)
            assert approval_policy.guidance_value(shown, limit, prose=prose) == shown
            assert len(shown) <= 10 * limit


@pytest.mark.parametrize("space", [r"\x20", r"\x09", r"\x0a"])
@pytest.mark.parametrize("prefix,secret", [("Bearer", "a1" * 20), ("password", "hunter2")])
def test_guidance_escaped_whitespace_keeps_its_redaction_character_class(space, prefix, secret):
    value = prefix + space + ("is" + space if prefix == "password" else "") + secret
    shown = approval_policy.guidance_value(value, prose=True)
    assert secret not in shown and "REDACTED" in shown
    assert approval_policy.guidance_value(shown, prose=True) == shown


@pytest.mark.parametrize("prose", [False, True], ids=["strict", "prose"])
@pytest.mark.parametrize("value", ["/home/alice bob", "token=1234 next", "https://host:8080 @user",
    "x" * 375 + "/" + "aB1cD2eF3gH4iJ5kL6mN7oP8" + "a" * 40,
    "x" * 384 + " token=secret12345", r"\x20", r"\x09", r"\x0a"])
def test_guidance_argon_redaction_vectors_are_fixpoints(value, prose):
    shown = approval_policy.guidance_value(value, prose=prose)
    assert approval_policy.guidance_value(shown, prose=prose) == shown
    if value in (r"\x20", r"\x09", r"\x0a"):
        assert shown == value


@pytest.mark.parametrize("repetitions", [8, 64, 700, 744])
@pytest.mark.parametrize("prose", [False, True], ids=["strict", "prose"])
def test_repeated_redactions_have_a_linear_line_step_budget(repetitions, prose):
    from aegis_core import redaction

    value = "token=aaaa " * repetitions
    tracked = {diagnostic_messages.__file__, approval_policy.__file__, redaction.__file__, difflib.__file__}
    steps, budget = [0], 256 * len(value) + 5000
    previous = sys.gettrace()

    def count(frame, event, arg):
        if event == "line" and frame.f_code.co_filename in tracked:
            steps[0] += 1
            if steps[0] > budget:
                pytest.fail("guidance exceeded its linear line-step budget")
        return count

    try:
        sys.settrace(count)
        shown = approval_policy.guidance_value(value, prose=prose)
    finally:
        sys.settrace(previous)
    assert steps[0] > 0
    assert "aaaa" not in shown and "REDACTED" in shown
    assert approval_policy.guidance_value(shown, prose=prose) == shown


@pytest.mark.parametrize("value,secret", [
    ("-----BEGIN " + "PRIVATE KEY-----\nprivate_material\n-----END " + "PRIVATE KEY-----", "private_material"),
    ("https://user:actual_password@example.test/path", "actual_password"),
    ("eyJ" + "a" * 16 + "." + "b" * 12 + "." + "c" * 12, "a" * 16),
    ("AKIA" + "A" * 16, "A" * 16), ("ASIA" + "A" * 16, "A" * 16),
    ("AGPA" + "A" * 16, "A" * 16),
    ("ghp_" + "a" * 36, "a" * 36), ("gho_" + "b" * 36, "b" * 36),
    ("github_pat_" + "c" * 30, "c" * 30), ("glpat-" + "d" * 30, "d" * 30),
    ("sk_live_" + "e" * 24, "e" * 24), ("sk-" + "f" * 30, "f" * 30),
    ("AIza" + "g" * 30, "g" * 30), ("xoxb-" + "h" * 24, "h" * 24),
    ("Bearer\t" + "a1" * 20, "a1" * 20),
    ("token=secret12345", "secret12345"), ("password\tis\nhunter2", "hunter2"),
    ("person@example.test", "person@example.test"), ("/home/alice/project", "alice"),
    ("1.2.3.4", "1.2.3.4"), ("aB1cD2eF3gH4iJ5kL6mN7oP8", "aB1cD2eF3gH4iJ5kL6mN7oP8"),
], ids=["pem", "url", "jwt", "aws-access", "aws-session", "aws-id", "github", "github-oauth",
        "github-pat", "gitlab", "service-key", "openai", "google", "slack", "bearer", "keyed", "password-is",
        "email", "home", "ip", "entropy"])
def test_redaction_replacement_batches_reconstruct_every_family_without_secret_payloads(value, secret):
    from aegis_core.redaction import redact_insight_text

    state, batches = [value], []

    def observe(spans):
        assert isinstance(spans, tuple) and spans
        source, parts, cursor = state[0], [], 0
        for start, end, replacement in spans:
            assert 0 <= cursor <= start <= end <= len(source)
            assert secret not in replacement
            parts.extend((source[cursor:start], replacement))
            cursor = end
        parts.append(source[cursor:])
        state[0] = "".join(parts)
        batches.append(spans)

    ordinary = redact_insight_text(value, max_len=81920)
    assert secret not in ordinary
    assert redact_insight_text(value, max_len=81920, on_replacements=None) == ordinary
    observed = redact_insight_text(value, max_len=81920, on_replacements=observe)
    assert batches and observed == ordinary == " ".join(state[0].split())


def test_replacement_spans_keep_only_explicit_backreference_context():
    from aegis_core import redaction
    from tests.unit.cli.test_check_ci_push import REDACTION_FAMILY_PROBES

    for index, (name, value, _secret, _mask) in enumerate(REDACTION_FAMILY_PROBES):
        pattern, replacement = (redaction._TEXT_REDACTIONS[index] if index < len(redaction._TEXT_REDACTIONS)
                                else (redaction.CANDIDATE_TOKEN_RE, "[REDACTED_HIENT]"))
        match = pattern.search(value)
        start, end, payload = match.start(), match.end(), match.expand(replacement)
        if replacement.startswith(r"\1"):
            start, payload = match.end(1), match.expand(replacement[2:])
            if replacement.endswith("@"):
                end, payload = end - 1, payload[:-1]
        batches = []
        observed = redaction.redact_insight_text(value, 81920, on_replacements=batches.append)
        # ROUND-8c drops privacy reinterpretation of this original family span.
        assert batches[0] == ((start, end, payload),), name
        assert observed == redaction.redact_insight_text(value, 81920), name
    batches = []
    redaction.redact_insight_text("token=[REDACTED] /home/~user", on_replacements=batches.append)
    assert batches == []


def test_raising_redaction_callback_propagates_without_returning_partial_text():
    from aegis_core.redaction import redact_insight_text

    def stop(spans):
        raise RuntimeError("observer failed")

    with pytest.raises(RuntimeError, match="^observer failed$"):
        redact_insight_text("token=secret12345 and person@example.test", on_replacements=stop)


def test_redaction_batches_use_the_current_pass_coordinates_across_families():
    from aegis_core.redaction import redact_insight_text

    secrets = ("a" * 36, "hunter2", "alice", "person@example.test", "1.2.3.4")
    value = "λ\t" + "\t".join(("ghp_" + secrets[0], "password is hunter2", "/home/alice/file",
                              "person@example.test", "1.2.3.4"))
    state, batches = [value], []

    def observe(spans):
        source, parts, cursor = state[0], [], 0
        for start, end, replacement in spans:
            assert cursor <= start <= end <= len(source)
            assert not any(secret in replacement for secret in secrets)
            parts.extend((source[cursor:start], replacement))
            cursor = end
        parts.append(source[cursor:])
        state[0] = "".join(parts)
        batches.append(spans)

    result = redact_insight_text(value, max_len=81920, on_replacements=observe)
    # ROUND-6 unions all families in one pass over the original source.
    assert len(batches) == 1
    assert result == redact_insight_text(value, max_len=81920) == " ".join(state[0].split())
    assert not any(secret in result for secret in secrets)


@pytest.mark.parametrize("value", ["1.2.3.4 " * 700, "person@example.test " * 200, "token=aaaa " * 700],
                         ids=["ip", "email", "keyed"])
@pytest.mark.parametrize("limit", [37, 40, 43, 397, 399, 400, 403, 4095, 4096])
def test_clipping_repeated_redactions_never_splits_an_earlier_mask(value, limit):
    shown = approval_policy.guidance_value(value, limit, prose=True)
    assert shown.count("[") == shown.count("]")
    assert approval_policy.guidance_value(shown, limit, prose=True) == shown


@pytest.mark.parametrize("limit", [37, 40, 43, 397, 399, 400, 403, 4095, 4096])
def test_clipping_repeated_masks_covers_every_shared_redaction_family(limit):
    from tests.unit.cli.test_check_ci_push import REDACTION_BOUNDARIES

    for probe, _boundary in REDACTION_BOUNDARIES.values():
        value = (probe + " ") * min(100, 8192 // (len(probe) + 1))
        shown = _within_redaction_budget(lambda: approval_policy.guidance_value(value, limit, prose=True), len(value))
        assert shown.count("[") == shown.count("]")
        assert approval_policy.guidance_value(shown, limit, prose=True) == shown
        assert not any(shown.endswith(part) for part in ("~", "~u", "~us", "~use"))


@pytest.mark.parametrize("value", ["ordinary\twords\nend", "token=[REDACTED]", "token=[REDACTEDx]",
    "x" * 5000 + " token=secret12345", "-----BEGIN " + "PRIVATE KEY-----\nunterminated"],
    ids=["whitespace", "already-redacted", "partially-redacted", "oversized", "unterminated-pem"])
@pytest.mark.parametrize("limit", [0, 40, 300, 81920])
def test_redaction_callback_preserves_legacy_bounds_and_formatting(value, limit):
    from aegis_core.redaction import redact_insight_text

    payloads = []
    ordinary = redact_insight_text(value, max_len=limit)
    assert redact_insight_text(value, max_len=limit, on_replacements=payloads.append) == ordinary
    assert all("secret12345" not in replacement and "unterminated" not in replacement
               for spans in payloads for _start, _end, replacement in spans)


@pytest.mark.parametrize("value,expected", [
    ("Fix the bug", "Fix the bug"),
    ("Fix . , : - _ / @ + # = café 漢字", "Fix . , : - _ / @ + # = café 漢字"),
    ("$(id) `id`; &", r"\x24\x28id\x29 \x60id\x60\x3b \x26"),
    ("'\"|<>!?*~\\", r"\x27\x22\x7c\x3c\x3e\x21?*~\x5c"),
    ("src/*.py 'quoted' (parentheses);gm1b", r"src/*.py \x27quoted\x27 \x28parentheses\x29\x3bgm1b"),
])
def test_guidance_prose_preserves_readable_text_and_escapes_shell_characters(value, expected):
    assert approval_policy.guidance_value(value, prose=True) == expected


@pytest.mark.parametrize("helper", ["guidance_value", "receipt_value"])
def test_guidance_value_omits_oversized_data_before_canonicalization(monkeypatch, helper):
    def premature(*args, **kwargs):
        raise AssertionError("display value reached canonicalization")
    monkeypatch.setattr(diagnostic_messages, "primitives", SimpleNamespace(sanitize_display=premature))
    render = getattr(approval_policy, helper)
    omitted = "[diagnostic omitted: too_large]" if helper == "receipt_value" else "diagnostic_omitted_too_large"
    assert render("x" * (8 * 1024 + 1)) == omitted
    with pytest.raises(AssertionError, match="display value reached canonicalization"):
        render("ordinary")


@pytest.mark.parametrize("helper", ["clip_rendered_text", "guidance_value", "receipt_value"])
@pytest.mark.parametrize("call_steps", [False, True], ids=["lines", "calls"])
def test_short_display_work_has_a_bounded_budget(helper, call_steps):
    render = getattr(approval_policy, helper)
    assert _within_redaction_budget(lambda: render("ordinary"), 8, call_steps=call_steps) == "ordinary"


def _repr_sites(source):
    """Locate ordinary repr formatting, including nested guidance expressions."""
    sites = set()
    class Visitor(ast.NodeVisitor):
        owner = "<module>"

        def visit_FunctionDef(self, node):
            previous, self.owner = self.owner, node.name
            self.generic_visit(node)
            self.owner = previous

        def visit_FormattedValue(self, node):
            if node.conversion == ord("r"):
                sites.add((self.owner, ast.unparse(node.value)))
            self.generic_visit(node)

        def visit_Call(self, node):
            if (isinstance(node.func, ast.Name) and node.func.id == "repr") \
                    or (isinstance(node.func, ast.Attribute) and node.func.attr == "repr"):
                sites.add((self.owner, ast.unparse(node)))
            if isinstance(node.func, ast.Attribute) and node.func.attr in ("format", "format_map") \
                    and isinstance(node.func.value, ast.Constant) and isinstance(node.func.value.value, str):
                if any(conversion == "r" for _literal, _name, _spec, conversion in Formatter().parse(node.func.value.value)):
                    sites.add((self.owner, ast.unparse(node)))
            self.generic_visit(node)
    Visitor().visit(ast.parse(source))
    return sites


@pytest.mark.parametrize("expression", ["f'Base: {value!r}'", "repr(value)", "builtins.repr(value)", "'Base: {!r}'.format(value)",
                                        "'Base: {value!r}'.format_map(values)"])
def test_guidance_repr_guard_detects_each_formatting_surface(expression):
    assert len(_repr_sites("def hint(value, values):\n    return " + expression)) == 1


def _assert_guidance_without_repr(root, *, excluded=()):
    from tests.unit.cli.test_check_ci_push import SWEPT_OUTPUT_MODULES

    exceptions = set()
    sites = {(path, owner, expression) for path in SWEPT_OUTPUT_MODULES if path not in excluded
             for owner, expression in _repr_sites((root / path).read_text(encoding="utf-8"))}
    assert sites - exceptions == set(), "guidance must use the inert display helper: " + str(sorted(sites - exceptions))
    assert exceptions - sites == set(), "remove stale non-guidance repr exceptions"


def test_guidance_in_swept_files_never_uses_repr():
    _assert_guidance_without_repr(Path(__file__).resolve().parents[3])


@pytest.mark.parametrize("expression,expected", [("f'{value!r}'", "value"), ("repr(value)", "repr(value)")],
                         ids=["fstring", "repr"])
def test_guidance_repr_census_detects_owner_mutations(tmp_path, expression, expected):
    from tests.unit.cli.test_check_ci_push import SWEPT_OUTPUT_MODULES

    root = Path(__file__).resolve().parents[3]
    owner = "aegis_core/diagnostic_messages.py"
    for filename in SWEPT_OUTPUT_MODULES:
        target = tmp_path / filename
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text((root / filename).read_text(encoding="utf-8"), encoding="utf-8")
    source = (root / owner).read_text(encoding="utf-8")
    (tmp_path / owner).write_text(source, encoding="utf-8")
    _assert_guidance_without_repr(tmp_path)
    (tmp_path / owner).write_text(source + "\n\ndef census_mutation(value):\n    return " + expression + "\n",
                                 encoding="utf-8")
    _assert_guidance_without_repr(tmp_path, excluded=(owner,))
    with pytest.raises(AssertionError) as error:
        _assert_guidance_without_repr(tmp_path)
    assert str(error.value).splitlines()[0] == \
        "guidance must use the inert display helper: " + str([(owner, "census_mutation", expected)])


@pytest.fixture
def _policy_environment(tmp_path, monkeypatch):
    home = hg.Home(tmp_path / "home")
    for name, value in home.env.items():
        monkeypatch.setenv(name, value)
    for name in ("GITHUB_EVENT_PATH", "GITHUB_EVENT_NAME", "GITHUB_BASE_REF", "GITHUB_REF", "GITHUB_REF_NAME", "GIT_CONFIG_GLOBAL"):
        monkeypatch.delenv(name, raising=False)


@pytest.mark.parametrize("base_policy", [None, {"main": "none", "*": "signature"},
                                         {"main": "signature", "*": "none"}],
                         ids=["legacy", "known-none", "known-signature"])
@pytest.mark.parametrize("form", [
    "main", "origin/main", "refs/remotes/origin/main", "refs/heads/main",
    "v1.2", "refs/tags/v1.2", "ambiguous", "FETCH_HEAD", "ORIG_HEAD",
    "HEAD@{1}", "@{u}", "@{upstream}", "oid", "short", "absent-remote",
    "tree", "blob", "alias", "upstream/main", "origin/HEAD", "refs/aegis/example", "empty",
    "origin/HEAD-direct", "team/fork/main", "refs/remotes/team/fork/main", "slash-upstream",
    "unknown/main", "refs/heads/HEAD", "refs/remotes/team/fork/HEAD", "refs/remotes/origin/release+1",
])
def test_git_selector_table_agrees_across_public_commands(tmp_path, _policy_environment, monkeypatch, capsys, base_policy, form):
    if not hg.git_ok():
        pytest.skip("needs git")
    project = hg.Repo(tmp_path / "project", hg.Home(tmp_path / "home"))
    project.write(".aegis/config.json", json.dumps({"approvals": base_policy} if base_policy is not None else {}))
    project.write("README.md", "tag base\n")
    older = project.commit("tag base")
    project.write("README.md", "branch base\n")
    base = project.commit("branch base")
    project.git("update-ref", "refs/remotes/origin/main", base)
    project.git("update-ref", "refs/remotes/upstream/main", base)
    project.git("update-ref", "refs/remotes/team/fork/main", base)
    project.git("update-ref", "refs/remotes/team/fork/HEAD", base)
    project.git("update-ref", "refs/remotes/unknown/main", base)
    project.git("update-ref", "refs/remotes/origin/release+1", base)
    project.git("symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
    project.git("symbolic-ref", "refs/heads/alias", "refs/heads/main")
    project.git("update-ref", "refs/aegis/example", base)
    project.git("tag", "v1.2", base)
    project.git("tag", "ambiguous", older)
    project.git("branch", "ambiguous", base)
    for remote in ("origin", "upstream", "team", "team/fork"):
        project.git("remote", "add", remote, "/not-contacted")
    project.branch("work")
    project.git("branch", "--set-upstream-to=origin/main", "work")
    project.write(".github/workflows/ci.yml", "name: changed\n")
    head = project.commit("workflow")
    (project.root / ".git" / "FETCH_HEAD").write_text(base + "\n", encoding="ascii")
    project.git("update-ref", "ORIG_HEAD", base)
    selector = form
    if form == "empty":
        selector = ""
    elif form == "origin/HEAD-direct":
        selector = "origin/HEAD"
        project.git("update-ref", "--no-deref", "refs/remotes/origin/HEAD", base)
    elif form == "slash-upstream":
        selector = "@{u}"
        project.git("config", "branch.work.remote", "team/fork")
        project.git("config", "branch.work.merge", "refs/heads/main")
    elif form == "refs/heads/HEAD":
        project.git("update-ref", "refs/heads/HEAD", base)
    elif form == "absent-remote":
        project.git("update-ref", "-d", "refs/remotes/origin/main")
        project.git("branch", "-f", "main", older)
        selector = "refs/remotes/origin/main"
    elif form == "oid":
        selector = base
    elif form == "short":
        selector = base[:12]
    elif form in ("tree", "blob"):
        selector = project.git("rev-parse", "HEAD^{tree}" if form == "tree" else "HEAD:README.md")
    unavailable = form in ("absent-remote", "tree", "blob")
    known = form in ("main", "origin/main", "refs/remotes/origin/main", "refs/heads/main",
                     "@{u}", "@{upstream}", "alias", "upstream/main", "origin/HEAD", "empty",
                     "team/fork/main", "refs/remotes/team/fork/main", "slash-upstream")
    expected_base = older if form == "ambiguous" else base
    expected_target = "main" if known else None
    expected_mode = (base_policy["main"] if known else "signature") if base_policy is not None else None
    original, observed = approval_policy.resolve_policy, []
    def observe(root, anchor, candidate, target):
        policy = original(root, anchor, candidate, target)
        observed.append((anchor, target, policy.mode))
        return policy
    # Observe the real public policy decision; no behaviour is replaced.
    monkeypatch.setattr(approval_policy, "resolve_policy", observe)
    for _ in range(2):
        for consumer in ("check", "approve", "core"):
            observed.clear()
            if consumer == "core":
                # Only CLI --base has omission semantics; the core base argument
                # is required, so an empty direct argument still refuses.
                if unavailable or form == "empty":
                    with pytest.raises(rule_integrity.IntegrityError, match="cannot resolve the base"):
                        rule_integrity.check_ci(project.root, selector)
                    assert not observed
                    continue
                report = rule_integrity.check_ci(project.root, selector)
                assert report.base == expected_base
                assert report.passed == (expected_mode != "signature")
            else:
                args = [consumer, "--workspace", str(project.root), "--base", selector, "--json"]
                if consumer == "check":
                    args += ["--ci", "--no-exec"]
                rc = cli.main(args)
                captured = capsys.readouterr()
                document = json.loads(captured.out)
                assert "Traceback" not in captured.out + captured.err
                if unavailable:
                    assert rc == 1 and document["code"] == ("base_unavailable" if consumer == "check" else "no_base")
                    action = document["next_action"] if consumer == "check" else document["reason"]
                    assert "fetch it or pass the full commit id" in action
                    if form == "absent-remote":
                        assert "fetch origin" in action
                    assert not observed
                    continue
                if consumer == "check":
                    assert rc == int(expected_mode == "signature")
                    assert document["scope"]["base"] == expected_base
                    assert document.get("approval_mode") == expected_mode
                else:
                    assert rc == 1 and document["code"] == ("not_required" if expected_mode == "none" else "no_key")
                assert "fetch-depth" not in captured.out + captured.err
            assert observed == [(expected_base, expected_target, expected_mode)]
        assert project.head() == head


@pytest.mark.parametrize("has_map", [False, True])
@pytest.mark.parametrize("failure", ["oversized", "too-many", "invalid-name", "nul", "encoding",
                                    "nonzero", "timeout", "ambiguous", "empty"])
def test_remote_inventory_failure_is_fixed_or_unknown(tmp_path, _policy_environment, monkeypatch, capsys, has_map, failure):
    if not hg.git_ok():
        pytest.skip("needs git")
    project = hg.make_repo(tmp_path)
    project.write(".aegis/config.json", json.dumps({"approvals": {"main": "none", "*": "signature"}} if has_map else {}))
    base = project.commit("policy")
    project.git("branch", "-f", "main", base)
    project.git("remote", "add", "origin", "/not-contacted")
    project.git("update-ref", "refs/remotes/origin/main", base)
    project.write(".github/workflows/ci.yml", "name: changed\n")
    head = project.commit("workflow")
    original_run, original_policy, observed = gitsafe.run, approval_policy.resolve_policy, []
    replies = {"oversized": b"secret" * 12000, "too-many": b"origin\n" * 257,
               "invalid-name": b"origin secret\n", "nul": b"ori\x00secret\n", "encoding": b"\xffsecret\n",
               "nonzero": b"", "ambiguous": b"origin\norigin\n", "empty": b""}
    def inventory(args, *rest, **kwargs):
        if list(args) == ["remote"]:
            if failure == "timeout":
                raise gitsafe.GitError("secret remote timeout")
            return SimpleNamespace(returncode=int(failure == "nonzero"), stdout=replies[failure], stderr=b"secret")
        return original_run(args, *rest, **kwargs)
    def observe(root, anchor, candidate, target):
        policy = original_policy(root, anchor, candidate, target)
        observed.append((anchor, target, policy.mode))
        return policy
    monkeypatch.setattr(gitsafe, "run", inventory)
    monkeypatch.setattr(approval_policy, "resolve_policy", observe)
    unknown = failure in ("ambiguous", "empty")
    for _ in range(2):
        for command in ("check", "approve", "core"):
            observed.clear()
            if command == "core":
                if not unknown:
                    with pytest.raises(approval_policy.PolicyUnavailable, match="invalid_approval_policy"):
                        rule_integrity.check_ci(project.root, "origin/main")
                    continue
                report = rule_integrity.check_ci(project.root, "origin/main")
                assert report.passed == (not has_map)
            else:
                args = [command, "--workspace", str(project.root), "--base", "origin/main", "--json"]
                if command == "check":
                    args += ["--ci", "--no-exec"]
                rc = cli.main(args)
                captured = capsys.readouterr()
                document = json.loads(captured.out)
                assert "secret" not in captured.out + captured.err and "Traceback" not in captured.out + captured.err
                if not unknown:
                    assert rc == 1 and document["code"] == "invalid_approval_policy"
                    assert observed == []
                    continue
                if command == "check":
                    assert rc == int(has_map) and document.get("approval_mode") == ("signature" if has_map else None)
                else:
                    assert rc == 1 and document["code"] == "no_key"
            assert observed == [(base, None, "signature" if has_map else None)]
        assert project.head() == head


@pytest.mark.parametrize("has_map", [False, True])
def test_remote_inventory_retry_requeries_git(tmp_path, _policy_environment, monkeypatch, capsys, has_map):
    if not hg.git_ok():
        pytest.skip("needs git")
    project = hg.make_repo(tmp_path)
    project.write(".aegis/config.json", json.dumps({"approvals": {"main": "none", "*": "signature"}} if has_map else {}))
    base = project.commit("policy")
    project.git("branch", "-f", "main", base)
    project.git("remote", "add", "origin", "/not-contacted")
    project.git("update-ref", "refs/remotes/origin/main", base)
    project.write(".github/workflows/ci.yml", "name: changed\n")
    project.commit("workflow")
    original, failed = gitsafe.run, []
    def fail_once(args, *rest, **kwargs):
        if list(args) == ["remote"] and not failed:
            failed.append(True)
            raise gitsafe.GitError("secret remote timeout")
        return original(args, *rest, **kwargs)
    monkeypatch.setattr(gitsafe, "run", fail_once)
    for command in ("check", "approve", "core"):
        failed.clear()
        if command == "core":
            with pytest.raises(approval_policy.PolicyUnavailable, match="invalid_approval_policy"):
                rule_integrity.check_ci(project.root, "origin/main")
            report = rule_integrity.check_ci(project.root, "origin/main")
            assert report.base == base and report.passed
            assert report.approval_policy.target == ("main" if has_map else None)
            assert report.approval_policy.mode == ("none" if has_map else None)
            continue
        args = [command, "--workspace", str(project.root), "--base", "origin/main", "--json"]
        if command == "check":
            args += ["--ci", "--no-exec"]
        assert cli.main(args) == 1
        captured = capsys.readouterr()
        assert json.loads(captured.out)["code"] == "invalid_approval_policy" and "secret" not in captured.out + captured.err
        rc = cli.main(args)
        document = json.loads(capsys.readouterr().out)
        if command == "check":
            assert rc == 0 and document["scope"]["base"] == base
            assert document.get("approval_mode") == ("none" if has_map else None)
        else:
            assert rc == 1 and document["code"] == ("not_required" if has_map else "no_key")


def test_parallel_slash_remote_checks_share_the_target_table(repo, monkeypatch):
    base = repo.git("rev-parse", "main")
    for remote in ("team", "team/fork"):
        repo.git("remote", "add", remote, "/not-contacted")
    repo.git("update-ref", "refs/remotes/team/fork/main", base)
    original, ready = gitsafe.run, Barrier(2)
    def overlap(args, *rest, **kwargs):
        if list(args) == ["remote"]:
            ready.wait(timeout=10)
        return original(args, *rest, **kwargs)
    monkeypatch.setattr(gitsafe, "run", overlap)
    with ThreadPoolExecutor(max_workers=2) as executor:
        reports = list(executor.map(lambda _: rule_integrity.check_ci(repo.root, "team/fork/main"), range(4), timeout=30))
    assert all(report.base == base and report.approval_policy.target == "main"
               and report.approval_policy.mode == "signature" and not report.passed for report in reports)


def test_HEAD_is_unknown_even_when_the_policy_lists_it():
    assert approval_policy.mode_for({"HEAD": "none", "main": "signature"}, "HEAD") == "signature"
    assert approval_policy.mode_for({"HEAD/**": "none", "*": "signature"}, "HEAD/topic") == "none"


@pytest.mark.parametrize("failure", ["oversized", "multiline", "nonref", "invalidref", "timeout", "nul", "encoding"])
def test_git_classification_failure_is_bounded_and_fixed(tmp_path, _policy_environment, monkeypatch, capsys, failure):
    if not hg.git_ok():
        pytest.skip("needs git")
    project = hg.make_repo(tmp_path)
    project.write(".aegis/config.json", json.dumps({"approvals": {"main": "none", "*": "signature"}}))
    base = project.commit("policy")
    project.git("branch", "-f", "main", base)
    project.write(".github/workflows/ci.yml", "name: changed\n")
    project.commit("workflow")
    original = gitsafe.run
    outputs = {"oversized": b"secret" * 2000, "multiline": b"refs/heads/main\nrefs/heads/secret\n",
               "nonref": b"secret\n", "invalidref": b"refs/heads/../secret\n",
               "nul": b"refs/heads/secret\x00suffix\n", "encoding": b"refs/heads/\xff\n"}
    def malformed(args, *rest, **kwargs):
        if list(args[:2]) == ["rev-parse", "--symbolic-full-name"]:
            if failure == "timeout":
                raise gitsafe.GitError("secret timeout detail")
            return SimpleNamespace(returncode=0, stdout=outputs[failure], stderr=b"secret")
        return original(args, *rest, **kwargs)
    monkeypatch.setattr(gitsafe, "run", malformed)
    for _ in range(2):
        for command in ("check", "approve"):
            args = [command, "--workspace", str(project.root), "--base", "main", "--json"]
            if command == "check":
                args += ["--ci", "--no-exec"]
            assert cli.main(args) == 1
            captured = capsys.readouterr()
            assert json.loads(captured.out)["code"] == "invalid_approval_policy"
            assert "secret" not in captured.out + captured.err and "Traceback" not in captured.out + captured.err


@pytest.mark.parametrize("has_map", [False, True])
@pytest.mark.parametrize("invalid", ["nul", "surrogate"])
def test_invalid_selector_text_refuses_before_git(tmp_path, _policy_environment, monkeypatch, capsys, has_map, invalid):
    if not hg.git_ok():
        pytest.skip("needs git")
    project = hg.make_repo(tmp_path)
    project.write(".aegis/config.json", json.dumps({"approvals": {"*": "signature"}} if has_map else {}))
    project.commit("configuration")
    token = "ghp_" + "a" * 36
    selector = "origin/" + (token[:10] + "\x00" + token[10:] if invalid == "nul" else "bad\ud800")
    original, calls = gitsafe.resolve_commit, []
    def observe(root, ref):
        calls.append(ref)
        return original(root, ref)
    monkeypatch.setattr(gitsafe, "resolve_commit", observe)
    for _ in range(2):
        calls.clear()
        assert approval_policy.resolve_base(project.root, selector) is None
        assert calls == []
        assert cli.main(["check", "--ci", "--workspace", str(project.root), "--base", selector, "--no-exec", "--json"]) == 1
        captured = capsys.readouterr()
        assert json.loads(captured.out)["code"] == "base_unavailable"
        assert "Traceback" not in captured.out + captured.err and token not in captured.out + captured.err
        assert cli.main(["approve", "--workspace", str(project.root), "--base", selector, "--json"]) == 2
        captured = capsys.readouterr()
        assert not captured.out and "one line of printable text" in captured.err and token not in captured.err


def test_a_branch_named_after_a_commit_cannot_upgrade_its_unknown_target(tmp_path, _policy_environment, capsys):
    if not hg.git_ok():
        pytest.skip("needs git")
    project = hg.make_repo(tmp_path)
    project.write(".aegis/config.json", json.dumps({"approvals": {"main": "signature", "*": "none"}}))
    base = project.commit("policy")
    project.git("branch", "-f", "main", base)
    project.git("tag", "release", base)
    project.git("branch", base, base)
    project.write(".github/workflows/ci.yml", "name: changed\n")
    project.commit("workflow")
    for _ in range(2):
        for selector in ("release", base):
            rc = cli.main(["check", "--ci", "--workspace", str(project.root), "--base", selector, "--no-exec", "--json"])
            report = json.loads(capsys.readouterr().out)
            assert rc == 1 and report["scope"]["base"] == base
            assert report["approval_target"] is None and report["approval_mode"] == "signature"
            core = rule_integrity.check_ci(project.root, selector)
            assert not core.passed and core.approval_policy.target is None and core.approval_policy.mode == "signature"


@pytest.mark.parametrize("has_map", [False, True])
def test_resolved_unrelated_base_has_a_comparison_refusal(tmp_path, _policy_environment, capsys, has_map):
    if not hg.git_ok():
        pytest.skip("needs git")
    project = hg.make_repo(tmp_path)
    project.write(".aegis/config.json", json.dumps({"approvals": {"*": "signature"}} if has_map else {}))
    project.commit("policy")
    unrelated = project.git("commit-tree", "HEAD^{tree}", stdin="unrelated\n")
    for _ in range(2):
        for command in ("check", "approve"):
            args = [command, "--workspace", str(project.root), "--base", unrelated, "--json"]
            if command == "check":
                args += ["--ci", "--no-exec"]
            assert cli.main(args) == 1
            captured = capsys.readouterr()
            assert captured.out, "a comparison refusal must return its JSON code"
            assert json.loads(captured.out)["code"] == ("comparison_unavailable" if command == "check" else "no_common_history")
            assert "fetch-depth" not in captured.out + captured.err and "base_unavailable" not in captured.out + captured.err


@pytest.fixture
def repo(tmp_path, _policy_environment):
    if not hg.git_ok():
        pytest.skip("needs git")
    project = hg.make_repo(tmp_path)
    for remote in ("origin", "upstream"):
        project.git("remote", "add", remote, "/not-contacted")
    project.write(".aegis/config.json", json.dumps({"approvals": MAP}))
    project.commit("policy")
    project.git("branch", "-f", "main", "HEAD")
    project.write(".github/workflows/ci.yml", "name: changed\n")
    project.commit("workflow change")
    return project


@pytest.mark.parametrize("target,mode", [
    ("main", "signature"), ("develop", "review"), ("release/1", "review"),
    ("release/deep/1", "review"), ("feature/lane", "none"),
    (None, "signature"), ("bad\nbranch", "signature"), ("HEAD", "signature"),
])
def test_modes_preserve_findings_and_gate_only_signature(repo, target, mode):
    base = repo.git("rev-parse", "main") if target is None else "main"
    report = rule_integrity.check_ci(repo.root, base, target=target)
    document = report.as_dict()
    assert document["approval_mode"] == mode
    assert document["approval_target"] == (target if target and "\n" not in target and target != "HEAD" else None)
    assert document["policy_source"] == "base"
    assert document["owner_review_required"] == (mode == "review")
    assert report.passed == (mode != "signature")
    assert document["governance"]["categories"] == ["workflows"]


@pytest.mark.parametrize("head_policy", [{"*": "none"}, {"*": "signature"}, None])
def test_head_policy_can_only_tighten_the_mode_even_on_retry(repo, head_policy):
    repo.write(".aegis/config.json", json.dumps({} if head_policy is None else {"approvals": head_policy}))
    repo.commit("head policy edit")
    for target, expected in (("main", "signature"), ("develop", "review")):
        expected = "signature" if head_policy == {"*": "signature"} else expected
        for _ in range(2):
            report = rule_integrity.check_ci(repo.root, "main", target=target)
            assert report.as_dict()["approval_mode"] == expected
            assert report.passed == (expected == "review")
            assert report.as_dict()["policy_source"] == ("head" if target == "develop" and expected == "signature" else "base")


def test_specificity_is_independent_of_map_order():
    raw = {"*": "signature", "release/**": "review", "release/private/**": "none", "release/private/x": "signature"}
    for entries in (raw, dict(reversed(list(raw.items())))):
        parsed = approval_policy.parse_policy({"approvals": entries})
        assert approval_policy.mode_for(parsed, "release/private/x") == "signature"
        assert approval_policy.mode_for(parsed, "release/private/y") == "none"
        assert approval_policy.mode_for(parsed, "release/public") == "review"
        assert approval_policy.mode_for(parsed, "releases/public") == "signature"
        assert approval_policy.mode_for(parsed, "release") == "signature"


def test_oversized_base_is_refused_before_git_or_name_allocation(repo, monkeypatch):
    def unexpected(*args, **kwargs):
        pytest.fail("oversized base reached Git")
    monkeypatch.setattr(gitsafe, "resolve_commit", unexpected)
    assert approval_policy.resolve_base(repo.root, "origin/" + "x" * (8 * 1024)) is None


@pytest.mark.parametrize("value", [None, [], "none", {}, {"*": "bogus"}, {"*": []},
    {"bad\nbranch": "none"}, {"release/*": "review"}, {"../main": "none"},
    {"a/**/b": "none"}, {"x" * 256: "none"}, {"main.lock": "none"}, {1: "none"},
])
def test_malformed_maps_refuse_without_echoing_values(value):
    with pytest.raises(approval_policy.InvalidApprovalPolicy) as exc:
        approval_policy.parse_policy({"approvals": value})
    assert str(exc.value) == approval_policy.INVALID_DETAIL


@pytest.mark.parametrize("text", [
    '{"approvals": {"*": "bad"}}', '{"approvals": null}',
    '{"approvals":{"*":"none","*":"signature"}}', '{broken',
    '[' * 1100 + ']' * 1100, 'x' * (64 * 1024 + 1),
], ids=["unknown-mode", "null", "duplicate-key", "invalid-json", "deep-json", "oversized"])
def test_malformed_head_policy_refuses_repeated_checks(repo, text):
    repo.write(".aegis/config.json", text)
    repo.commit("invalid head")
    for _ in range(2):
        with pytest.raises(approval_policy.InvalidApprovalPolicy, match="invalid_approval_policy"):
            rule_integrity.check_ci(repo.root, "main", target="feature/x")


def test_invalid_base_uses_legacy_gate_and_reports_error(repo):
    repo.write(".aegis/config.json", '{"approvals": {"*": "bad"}}')
    repo.commit("old invalid policy")
    base = repo.head()
    repo.write(".aegis/config.json", '{}')
    repo.commit("repair policy")
    report = rule_integrity.check_ci(repo.root, base, target="feature/x")
    assert report.passed  # no signers at the base: the legacy tier-C governance rule
    assert report.as_dict()["approval_policy_error"] == approval_policy.INVALID_DETAIL
    assert "approval_mode" not in report.as_dict()


def test_signature_still_accepts_the_existing_approval_boundary(repo, monkeypatch):
    seen = []
    def approved(root, head, base):
        seen.append((head, base))
        return human_gate.Approval(True, "ok", "approved", head, "Human")
    monkeypatch.setattr(human_gate, "find_approval", approved)
    report = rule_integrity.check_ci(repo.root, "main", target="main")
    assert report.passed and seen == [(report.head, report.base)]


def test_parallel_checks_remain_bound_to_resolved_commits_when_ref_moves(repo, monkeypatch):
    base, head = repo.git("rev-parse", "main"), repo.head()
    original = gitsafe.tree_blobs
    moved = []
    def move_after_resolution(root, revision, **kwargs):
        if not moved:
            moved.append(True)
            repo.git("update-ref", "refs/heads/main", head)
        return original(root, revision, **kwargs)
    monkeypatch.setattr(gitsafe, "tree_blobs", move_after_resolution)
    with ThreadPoolExecutor(max_workers=2) as executor:
        reports = list(executor.map(lambda _: rule_integrity.check_ci(repo.root, base, head, target="main"), range(4)))
    assert all(report.base == base and report.head == head and not report.passed for report in reports)


def test_oversized_blob_is_refused_before_content_read(repo, monkeypatch):
    repo.write(".aegis/config.json", "x" * (64 * 1024 + 1))
    repo.commit("oversized")
    actual_read, actual_run = gitsafe.read_object, gitsafe.run
    reads, commands = [], []
    def watch(root, oid, limit):
        reads.append(limit)
        return actual_read(root, oid, limit)
    def run(args, *rest, **kwargs):
        commands.append(tuple(args))
        return actual_run(args, *rest, **kwargs)
    monkeypatch.setattr(gitsafe, "read_object", watch)
    monkeypatch.setattr(gitsafe, "run", run)
    with pytest.raises(approval_policy.InvalidApprovalPolicy):
        approval_policy.read_policy(repo.root, repo.head())
    assert reads == [64 * 1024]
    assert ("cat-file", "--batch-check") in commands
    assert ("cat-file", "--batch") not in commands


@pytest.mark.parametrize("text", ['{broken', '[]', 'x' * (64 * 1024 + 1)], ids=["unparseable", "non-object", "oversized"])
def test_no_policy_keeps_legacy_for_unusable_head_config(repo, text):
    repo.write(".aegis/config.json", '{}')
    base = repo.commit("legacy base")
    repo.write(".aegis/config.json", text)
    head = repo.commit("legacy config")
    for _ in range(2):
        report = rule_integrity.check_ci(repo.root, base, head, target="main")
        assert report.passed
        assert not any(key.startswith("approval_") or key == "policy_source" for key in report.as_dict())


def test_introduced_valid_policy_only_adds_owner_review_to_legacy_report(repo):
    repo.write(".aegis/config.json", '{}')
    base = repo.commit("legacy base")
    repo.write(".aegis/config.json", '{"v":1}')
    repo.commit("ordinary legacy configuration")
    baseline = rule_integrity.check_ci(repo.root, base).as_dict()
    repo.write(".aegis/config.json", json.dumps({"approvals": {"*": "signature"}}))
    repo.commit("introduce map")
    result = rule_integrity.check_ci(repo.root, base, target="main").as_dict()
    assert "owner_review_required" not in result
    rows = result.pop("owner_review_findings")
    assert [row["code"] for row in rows] == ["approval_policy_introduced"]
    for document in (baseline, result):
        document.pop("checked_at")
        document["scope"]["head"] = "comparison-head"
    assert json.dumps(result, sort_keys=True) == json.dumps(baseline, sort_keys=True)


@pytest.mark.parametrize("introduced", [False, True])
@pytest.mark.parametrize("with_signers", [False, True])
def test_owner_policy_report_respects_base_signers(repo, introduced, with_signers):
    if with_signers:
        repo.write("allowed_signers", hg.allowed_signers_text(hg.hardware_public_key()))
    repo.write(".aegis/config.json", json.dumps({} if introduced else {"approvals": {"*": "signature"}}))
    base = repo.commit("base policy")
    repo.write(".aegis/config.json", json.dumps({"approvals": {"*": "none"}}))
    head = repo.commit("policy change")
    def run(_):
        report = rule_integrity.check_ci(repo.root, base, head, target="main")
        assert report.weakenings == ()
        assert report.passed == (introduced and not with_signers)
        return tuple(row.code for row in report.owner_review_required)
    expected = () if with_signers else ("approval_policy_introduced" if introduced else "approval_mode_lowered",)
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(run, range(6))) == [expected] * 6


@pytest.mark.parametrize("before,after,lowered", [
    ({"release/**": "signature", "*": "none"}, {"*": "review"}, ["release/**"]),
    ({"release/**": "review", "*": "none"}, {"release/private/**": "none", "*": "signature"}, ["release/private/**"]),
    ({"main": "signature", "*": "none"}, {"main": "none", "*": "signature"}, ["main"]),
    ({"release/**": "review", "*": "none"}, {"release/private/**": "signature", "*": "signature"}, []),
])
def test_owner_policy_report_compares_all_target_regions(repo, before, after, lowered):
    repo.write(".aegis/config.json", json.dumps({"approvals": before}))
    base = repo.commit("base policy")
    repo.write(".aegis/config.json", json.dumps({"approvals": after}))
    head = repo.commit("policy change")
    for _ in range(2):
        report = rule_integrity.check_ci(repo.root, base, head, target="unrelated")
        assert [row.rule for row in report.owner_review_required] == lowered
        assert not report.weakenings


def test_policy_read_refusal_is_not_memoized(repo, monkeypatch):
    commit = repo.head()
    original, calls = gitsafe.read_object, []
    def fail_once(*args, **kwargs):
        calls.append(True)
        if len(calls) == 1:
            raise gitsafe.GitError("untrusted timeout detail")
        return original(*args, **kwargs)
    monkeypatch.setattr(gitsafe, "read_object", fail_once)
    with gitsafe.memo():
        with pytest.raises(approval_policy.PolicyUnavailable) as error:
            approval_policy.read_policy(repo.root, commit)
        assert str(error.value) == approval_policy.POLICY_UNAVAILABLE_DETAIL
        assert approval_policy.read_policy(repo.root, commit) == MAP
        assert approval_policy.read_policy(repo.root, commit) == MAP
    assert len(calls) == 2


@pytest.mark.parametrize("value", [None, [], {"*": "bad"}])
def test_introduced_malformed_map_refuses_on_a_legacy_base(repo, value):
    repo.write(".aegis/config.json", '{}')
    base = repo.commit("legacy base")
    repo.write(".aegis/config.json", json.dumps({"approvals": value}))
    repo.commit("invalid introduced map")
    with pytest.raises(approval_policy.InvalidApprovalPolicy, match="invalid_approval_policy"):
        rule_integrity.check_ci(repo.root, base)


@pytest.mark.parametrize("selector", ["short", "upstream/main", "origin/HEAD", "v1.2", "refs/tags/v1.2"])
def test_git_classifies_tag_commit_and_remote_selectors(repo, selector):
    base = repo.git("rev-parse", "main")
    repo.git("update-ref", "refs/remotes/upstream/main", base)
    repo.git("update-ref", "refs/remotes/origin/main", base)
    repo.git("symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
    repo.git("tag", "v1.2", base)
    selector = base[:8] if selector == "short" else selector
    report = rule_integrity.check_ci(repo.root, selector)
    # Git names both remote selectors as refs/remotes/R/main; tags and oids
    # remain unknown. This is the round-8 table, not a spelling heuristic.
    target = "main" if selector in ("upstream/main", "origin/HEAD") else None
    assert not report.passed and report.as_dict()["approval_target"] == target
    assert report.as_dict()["approval_mode"] == "signature"


@pytest.mark.parametrize("selector", ["main", "origin/main", "refs/remotes/origin/main", "refs/heads/main"])
def test_known_branch_selectors_keep_the_branch_target(repo, selector):
    repo.git("update-ref", "refs/remotes/origin/main", repo.git("rev-parse", "main"))
    report = rule_integrity.check_ci(repo.root, selector)
    assert report.as_dict()["approval_target"] == "main" and not report.passed


@pytest.mark.parametrize("selector", ["origin/main", "main", "refs/remotes/origin/main", "refs/heads/main"])
def test_parallel_checks_pin_gits_selected_policy_despite_a_shadowing_tag(repo, selector):
    base, head = repo.git("rev-parse", "refs/heads/main"), repo.head()
    repo.git("update-ref", "refs/remotes/origin/main", base)
    older = repo.git("rev-parse", "refs/heads/main^")
    repo.git("tag", selector, older)
    with ThreadPoolExecutor(max_workers=2) as executor:
        reports = list(executor.map(lambda _: rule_integrity.check_ci(repo.root, selector, head), range(4)))
    ambiguous = selector in ("main", "origin/main")
    # Git pins the tag for bare ambiguity and the branch for qualified input.
    # Both have empty symbolic-full-name output in this collision: UNKNOWN.
    assert all(report.base == (older if ambiguous else base) and report.passed == ambiguous for report in reports)
    assert all(report.approval_policy.mode == (None if ambiguous else "signature")
               and report.approval_policy.target is None for report in reports)


@pytest.mark.parametrize("shadow", ["tag", "local"])
@pytest.mark.parametrize("selector", ["origin/feature/x", "refs/remotes/origin/feature/x", "refs/heads/feature/x"])
def test_git_classifies_ref_shaped_local_branches_and_tags(repo, shadow, selector):
    base = repo.git("rev-parse", "main")
    repo.git("tag" if shadow == "tag" else "branch", selector, base)
    for _ in range(2):
        # Git identifies a local shadow as refs/heads/<selector>, hence a known
        # local branch under the new table. A tag remains unknown and strictest.
        target = selector if shadow == "local" else None
        assert approval_policy.resolve_comparison(repo.root, selector, commit=base).target == target
        report = rule_integrity.check_ci(repo.root, selector)
        assert report.base == base and report.approval_policy.target == target
        assert report.approval_policy.mode == ("none" if shadow == "local" else "signature")
        assert report.passed == (shadow == "local")


def test_branch_identity_read_failure_refuses_but_pinned_oid_has_unknown_target(repo, monkeypatch):
    base = repo.git("rev-parse", "refs/heads/main")
    def unavailable(*args, **kwargs):
        raise gitsafe.GitError("secret ref read failure")
    monkeypatch.setattr(gitsafe, "read_ref", unavailable)
    for _ in range(2):
        with pytest.raises(approval_policy.PolicyUnavailable) as error:
            approval_policy.resolve_comparison(repo.root, "main", commit=base)
        assert str(error.value) == approval_policy.POLICY_UNAVAILABLE_DETAIL
        report = rule_integrity.check_ci(repo.root, base)
        assert report.approval_policy.target is None and report.approval_policy.mode == "signature"
        assert not report.passed and "secret" not in json.dumps(report.as_dict())


def test_branch_moving_after_base_resolution_cannot_reclassify_the_pinned_commit(repo, monkeypatch):
    base, head = repo.git("rev-parse", "main"), repo.head()
    repo.git("update-ref", "refs/remotes/origin/develop", base)
    original = gitsafe.resolve_commit
    def move(root, revision):
        commit = original(root, revision)
        if revision == "origin/develop":
            repo.git("update-ref", "refs/remotes/origin/develop", head)
        return commit
    monkeypatch.setattr(gitsafe, "resolve_commit", move)
    report = rule_integrity.check_ci(repo.root, "origin/develop")
    assert report.base == base and report.approval_policy.target is None
    assert report.approval_policy.mode == "signature" and not report.passed


@pytest.mark.parametrize("explicit", [False, True])
def test_push_policy_base_is_pinned_across_fallback_ref_move(repo, monkeypatch, explicit):
    repo.write(".aegis/config.json", '{}')
    before = repo.commit("legacy predecessor")
    repo.write(".aegis/config.json", json.dumps({"approvals": MAP}))
    protected = repo.commit("reviewed fallback policy")
    repo.write(".aegis/config.json", json.dumps({"approvals": {"*": "none"}}))
    head = repo.commit("candidate loosens policy")
    repo.git("update-ref", "refs/remotes/origin/main", protected)
    original = gitsafe.read_ref
    def move(root, revision):
        result = original(root, revision)
        if revision == "refs/remotes/origin/main" and result != head:
            repo.git("update-ref", "refs/remotes/origin/main", head)
        return result
    monkeypatch.setattr(gitsafe, "read_ref", move)
    pinned = approval_policy.push_base(repo.root, before, "origin/main", head, explicit=explicit)
    assert pinned == (protected if explicit else before)
    report = rule_integrity.check_ci(repo.root, pinned, head, target="main")
    assert report.passed == (not explicit)
    def retry(_):
        try:
            return approval_policy.push_base(repo.root, before, "origin/main", head, explicit=explicit)
        except approval_policy.BaseUnavailable as exc:
            assert str(exc) == (approval_policy.COMPARISON_UNAVAILABLE_DETAIL if explicit
                                else approval_policy.BASE_UNAVAILABLE_DETAIL)
            return "refused"
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(retry, range(4)))
    assert results == (["refused"] * 4 if explicit else [before] * 4)


@pytest.mark.parametrize("supplied_target", [False, True])
def test_parallel_pr_checks_never_infer_a_target_from_review_identity(repo, supplied_target):
    base, head = repo.git("rev-parse", "main"), repo.head()
    pull = human_gate.PullRequest(1, "agent", head, "feature/x")
    kwargs = {"target": None} if supplied_target else {}
    with ThreadPoolExecutor(max_workers=2) as executor:
        reports = list(executor.map(lambda _: rule_integrity.check_ci(repo.root, base, head, pull_request=pull, **kwargs), range(4)))
    assert all(not report.passed and report.approval_policy.target is None
               and report.approval_policy.mode == "signature" for report in reports)


def test_explicit_zero_before_fallback_stays_pinned_when_the_branch_moves(repo, monkeypatch):
    base, head = repo.git("rev-parse", "refs/heads/main"), repo.head()
    repo.git("update-ref", "refs/remotes/origin/main", base)
    original = gitsafe.read_ref
    def move(root, revision):
        commit = original(root, revision)
        if revision == "refs/remotes/origin/main" and commit == base:
            repo.git("update-ref", "refs/remotes/origin/main", head)
        return commit
    monkeypatch.setattr(gitsafe, "read_ref", move)
    pinned = approval_policy.push_base(repo.root, "0" * 40, "origin/main", head, explicit=True)
    assert pinned == base
    with ThreadPoolExecutor(max_workers=2) as executor:
        reports = list(executor.map(lambda _: rule_integrity.check_ci(repo.root, pinned, head, target="main"), range(4)))
    assert all(report.base == base and not report.passed for report in reports)
    for _ in range(2):
        assert approval_policy.push_base(repo.root, "0" * 40, "origin/main", head, explicit=True) == head


@pytest.mark.parametrize("failure", ["tree", "blob"])
def test_unreadable_committed_policy_never_becomes_legacy(repo, monkeypatch, failure):
    def unavailable(*args, **kwargs):
        raise gitsafe.GitError("secret object read failure")
    if failure == "tree":
        monkeypatch.setattr(gitsafe, "tree_blobs", unavailable)
    else:
        monkeypatch.setattr(gitsafe, "read_object", unavailable)
    for _ in range(2):
        with pytest.raises(approval_policy.InvalidApprovalPolicy, match="invalid_approval_policy") as exc:
            rule_integrity.check_ci(repo.root, "main", target="main")
        assert "secret" not in str(exc.value)


def test_ungated_targets_follow_permits_unsigned_and_stay_sorted():
    """Signature keeps the gate, including when no signers exist; the helper has no signer input."""
    assert approval_policy.ungated_targets(None) == ()
    assert approval_policy.ungated_targets({}) == ()
    assert approval_policy.ungated_targets({"main": "signature", "release/**": "signature"}) == ()
    mixed = {"zeta": "none", "main": "signature", "alpha": "review", "mid": "none"}
    assert approval_policy.ungated_targets(mixed) == (
        ("alpha", "review"), ("mid", "none"), ("zeta", "none"))
    parsed = approval_policy.parse_policy({"approvals": {"b": "review", "a": "none", "*": "signature"}})
    assert approval_policy.ungated_targets(parsed) == (("a", "none"), ("b", "review"))
    assert approval_policy.ungated_targets(approval_policy.parse_policy({})) == ()
    names = [f"t{index:03d}" for index in range(40, -1, -1)]
    policy = {name: ("signature" if index % 3 == 0 else "none" if index % 3 == 1 else "review")
              for index, name in enumerate(names)}
    found = approval_policy.ungated_targets(policy)
    assert found == tuple(sorted(
        (name, policy[name]) for name in names if approval_policy.Policy(mode=policy[name]).permits_unsigned))
    assert found == approval_policy.ungated_targets(dict(reversed(list(policy.items()))))


def test_ungated_targets_refuses_unbounded_input_before_the_predicate(monkeypatch):
    secret = "token=ghp_" + ("Z" * 20)
    calls = []

    class Boom:
        def __init__(self, mode=None):
            calls.append(mode)

        @property
        def permits_unsigned(self):
            raise AssertionError("predicate ran")

    monkeypatch.setattr(approval_policy, "Policy", Boom)
    oversized = {f"b{index}": "none" for index in range(approval_policy.MAX_PATTERNS + 1)}
    oversized[secret] = "none"
    with pytest.raises(approval_policy.InvalidApprovalPolicy) as exc:
        approval_policy.ungated_targets(oversized)
    assert calls == [] and secret not in str(exc.value) and "b0" not in str(exc.value)


def test_ungated_targets_refuses_overlong_names_and_non_maps():
    huge = "H" * 10000
    with pytest.raises(approval_policy.InvalidApprovalPolicy) as exc:
        approval_policy.ungated_targets({huge: "none"})
    assert huge not in str(exc.value) and "HHHH" not in str(exc.value)
    for bad in ("*", ["main"], 3, b"main"):
        with pytest.raises(approval_policy.InvalidApprovalPolicy) as exc:
            approval_policy.ungated_targets(bad)
        assert "main" not in str(exc.value)


def test_ungated_targets_validates_every_entry_before_the_predicate(monkeypatch):
    """A later bad entry refuses the whole map before any permits_unsigned call."""
    calls = []

    class Boom:
        def __init__(self, mode=None):
            calls.append(mode)

        @property
        def permits_unsigned(self):
            raise AssertionError("predicate ran")

    class Key(str):
        def __lt__(self, other):
            raise AssertionError("sorted")

        def __le__(self, other):
            raise AssertionError("sorted")

    monkeypatch.setattr(approval_policy, "Policy", Boom)
    samples = (
        {"*": "REVIEW"},
        {"main": "not-a-mode"},
        {"": "none"},
        {"main": "none", "H" * 10000: "none"},
    )
    for policy in samples:
        calls.clear()
        with pytest.raises(approval_policy.InvalidApprovalPolicy) as exc:
            approval_policy.ungated_targets(policy)
        assert calls == []
        text = str(exc.value)
        assert "REVIEW" not in text and "not-a-mode" not in text and "HHHH" not in text
    calls.clear()
    with pytest.raises(approval_policy.InvalidApprovalPolicy) as exc:
        approval_policy.ungated_targets({Key("*"): "none"})
    assert calls == [] and "sorted" not in str(exc.value)


def test_ungated_targets_retry_and_threads_return_the_same_tuple():
    policy = {"b": "none", "a": "review", "c": "signature"}
    expected = (("a", "review"), ("b", "none"))
    assert approval_policy.ungated_targets(policy) == expected
    assert approval_policy.ungated_targets(policy) == expected
    with ThreadPoolExecutor(max_workers=4) as executor:
        found = list(executor.map(lambda _: approval_policy.ungated_targets(dict(policy)), range(8)))
    assert found == [expected] * 8
