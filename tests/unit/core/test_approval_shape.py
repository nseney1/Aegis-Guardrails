"""The signed trailer block has one kind and one printable line per value."""
import re
import subprocess
import sys
from pathlib import Path

import pytest

from aegis_core import approval_shape


TRAILER = re.compile(r"^[ \t]*aegis-approve[ \t]*:[ \t]*(\S*)[ \t]*$", re.I | re.M)
VALUE = "a" * 64
LINE = f"Aegis-Approve: {VALUE}\n"


@pytest.mark.parametrize("prefix", ["approve\n\n", "chore: approve governance state\n\n", "older subject\n\nprose\n\n"])
@pytest.mark.parametrize("line", [LINE, LINE.upper(), " \taEgIs-ApPrOvE : " + VALUE + " \n"])
def test_one_expected_trailer_preserves_historical_subjects_and_spelling(prefix, line):
    assert approval_shape.refusal(prefix + line + "\n", TRAILER, "Aegis-Approve") is None


@pytest.mark.parametrize("extra", [
    "Aegis-Approve-Insight: " + VALUE + "\n",
    "Aegis-Exempt-Test: " + "b" * 40 + " reviewed\n",
    "\taegis-Unknown: hidden\n",
    "Aegis-Approve: malformed extra value\n",
    "Aegis-Approve\n",
])
@pytest.mark.parametrize("before", [True, False])
def test_even_malformed_or_unknown_aegis_lines_are_refused_on_either_side(extra, before):
    message = "approve\n\n" + (extra + LINE if before else LINE + extra)
    assert approval_shape.refusal(message, TRAILER, "Aegis-Approve")[0] == "invalid_message_shape"


@pytest.mark.parametrize("suffix", ["continued\n", "\ncontinued\n", "\tcontinued\n", "\r", "\u2028"])
def test_a_signed_value_cannot_continue_after_the_trailer(suffix):
    assert approval_shape.refusal("approve\n\n" + LINE + suffix, TRAILER, "Aegis-Approve")[0] == "invalid_message_shape"


def test_missing_or_duplicate_trailer_refuses_without_echoing_message():
    assert approval_shape.refusal("untrusted input", TRAILER, "Aegis-Approve")[0] == "invalid_message_shape"
    assert approval_shape.refusal(LINE + LINE, TRAILER, "Aegis-Approve") == (
        "multiple_trailers", "more than one Aegis-Approve trailer")


@pytest.mark.parametrize("metadata", [
    "Aegis-Check: tree=" + "b" * 40 + " exit=0\n",
    "Signed-off-by: Reviewer <reviewer@example.invalid>\n",
    "Co-Authored-By: Reviewer <reviewer@example.invalid>\n",
])
@pytest.mark.parametrize("before", [True, False])
def test_non_authority_trailers_are_allowed_before_or_after_authority(metadata, before):
    message = "approve\n\n" + (metadata + LINE if before else LINE + metadata)
    assert approval_shape.refusal(message, TRAILER, "Aegis-Approve") is None


@pytest.mark.parametrize("extra, reason", [
    ("Aegis-Approve-Insight: secret", "another Aegis authority line is present (line 4)"),
    ("Aegis-Manager-Approve: secret", "another Aegis authority line is present (line 4)"),
    ("Aegis-Future: secret", "an unknown Aegis line is present (line 4)"),
    ("Aegis-Check: secret", "an unknown Aegis line is present (line 4)"),
    ("continued secret", "the Aegis-Approve value must be one printable line"),
    ("\tSigned-off-by: secret", "the Aegis-Approve value must be one printable line"),
    (" Aegis-Check: tree=" + "b" * 40 + " exit=0", "the Aegis-Approve value must be one printable line"),
])
def test_refusal_reasons_identify_the_defect_without_echoing_values(extra, reason):
    assert approval_shape.refusal("approve\n\n" + LINE + extra + "\n", TRAILER, "Aegis-Approve") == (
        "invalid_message_shape", reason)


@pytest.mark.parametrize("reason", ["reviewed\ncontinued", "reviewed\rcontinued", "reviewed\u2028continued", "reviewed\x01hidden"])
def test_exemption_value_is_one_printable_line(reason):
    trailer = re.compile(r"^Aegis-Exempt-Test: ([a-f0-9]{40}) (\S[^\r\n]*)$", re.M)
    message = "approve\n\nAegis-Exempt-Test: " + "b" * 40 + " " + reason + "\n"
    assert approval_shape.refusal(message, trailer, "Aegis-Exempt-Test") == (
        "invalid_message_shape", "the Aegis-Exempt-Test value must be one printable line")


@pytest.mark.parametrize("message, code", [
    (LINE + "\n" * 65536, "message_too_large"),
    (LINE + ("é" * 4000 + "\n") * 9, "message_too_large"),
    (LINE + "x" * 8193, "message_line_too_long"),
], ids=["message-bytes", "utf8-bytes", "line-length"])
def test_limits_refuse_before_any_trailer_regex(message, code):
    class UnreachablePattern:
        def finditer(self, *_args):
            pytest.fail("regex ran before the message limits")

    verdict = approval_shape.refusal(message, UnreachablePattern(), "Aegis-Approve")
    assert verdict[0] == code


def test_metadata_adversaries_are_bounded_and_finish_under_a_subprocess_hang_guard():
    script = r'''
import re
from aegis_core import approval_shape
from aegis_core.approval_shape import MAX_MESSAGE_BYTES, MAX_LINE_LENGTH
assert (MAX_MESSAGE_BYTES, MAX_LINE_LENGTH) == (65536, 8192)
trailer = re.compile(r"^Aegis-Approve: (\S+)$", re.M)
authority = "Aegis-Approve: " + "a" * 64 + "\n"
large = "Signed-off-by:" + " " * (1024 * 1024) + "\r"
assert len(large) == 1048591
assert approval_shape.refusal(authority + large, trailer, "Aegis-Approve")[0] == "message_too_large"
near = "Signed-off-by:" + " " * (8191 - len("Signed-off-by:") - 1) + "\r"
assert len(near) == 8191
assert approval_shape.refusal(authority + near, trailer, "Aegis-Approve")[0] == "invalid_message_shape"
assert approval_shape.refusal(authority + near[:-1], trailer, "Aegis-Approve") is None
'''
    result = subprocess.run([sys.executable, "-c", script], cwd=Path(__file__).resolve().parents[3],
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr


def test_exact_message_and_line_limits_remain_compatible():
    prefix = ("x" * 8192 + "\n") * 7
    message = prefix + "x" * (65536 - len(prefix) - len(LINE) - 1) + "\n" + LINE
    assert len(message.encode("utf-8")) == 65536
    assert approval_shape.refusal(message, TRAILER, "Aegis-Approve") is None


def test_message_bounds_refuse_oversize_without_authority_scanning(monkeypatch):
    class UnreachablePattern:
        def search(self, *_args):
            pytest.fail("authority regex ran before the message limits")

    monkeypatch.setattr(approval_shape, "_AUTHORITY_LINE", UnreachablePattern())
    assert approval_shape.bounds_refusal("x" * 65537)[0] == "message_too_large"


@pytest.mark.parametrize("raw, code", [
    (b"chore: pasted\n\n" + b"x" * 9000 + b"\n", "message_line_too_long"),
    (b"work\n" + ("Я" * 6899 + "\n").encode("cp1251") * 4, "message_too_large"),
], ids=["long-line", "cp1251"])
@pytest.mark.parametrize("authority", [False, True], ids=["ordinary", "authority"])
def test_hook_authority_detection_depends_only_on_an_authority_line(raw, code, authority):
    message = raw.decode("utf-8", "surrogateescape") + ("\n" + LINE if authority else "")
    assert approval_shape.bounds_refusal(message)[0] == code
    assert approval_shape.has_authority_line(message) is authority
