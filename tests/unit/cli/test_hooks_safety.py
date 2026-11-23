"""aegis_cli.hooks.safety.log_gate_event: the safety gate's decision log, .aegis/state/gate_events.jsonl."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import re
import sys
from threading import Barrier

import pytest

import aegis_core.redaction_patterns as redaction_patterns
from aegis_cli.hooks.safety import log_gate_event, run_safety_gate


_KEY_PREFIX = "AK" + "IA"
_KEY_BODY = "0" * 16


def _rows(ws: Path) -> list:
    text = (ws / ".aegis" / "state" / "gate_events.jsonl").read_text(encoding="utf-8")
    return [json.loads(line) for line in text.splitlines()]


def test_each_decision_is_appended_with_its_command_and_any_reason(tmp_path: Path):
    (tmp_path / ".aegis").mkdir()

    log_gate_event("rm -rf build", "deny", "Recursive delete", tmp_path)
    log_gate_event("ls", "allow", "", tmp_path)

    deny, allow = _rows(tmp_path)
    assert (deny["command"], deny["decision"], deny["reason"]) == ("rm -rf build", "deny", "Recursive delete")
    assert (allow["command"], allow["decision"]) == ("ls", "allow")
    assert "reason" not in allow
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", deny["timestamp"])


def test_a_logged_command_keeps_only_its_first_200_characters(tmp_path: Path):
    (tmp_path / ".aegis").mkdir()
    cmd = "echo " + "x" * 300

    log_gate_event(cmd, "allow", "", tmp_path)

    (row,) = _rows(tmp_path)
    assert row["command"] == cmd[:200]


@pytest.mark.parametrize("split", ["\r", "\x85", "\v", "\f", "\0", "\x1b[31m"],
                         ids=["cr", "nel", "vt", "ff", "nul", "csi"])
def test_gate_log_masks_keys_split_by_ignored_controls(tmp_path: Path, split: str):
    (tmp_path / ".aegis").mkdir()

    log_gate_event(f"echo {_KEY_PREFIX}{split}{_KEY_BODY} --after", "allow", "", tmp_path)

    (row,) = _rows(tmp_path)
    assert _KEY_BODY not in row["command"]
    # ROUND-1g ruling: stored text ends at the first ESC or C1, so NEL and CSI withhold the key head.
    if split in ("\x85", "\x1b[31m"):
        assert row["command"] == "echo ..."
    else:
        assert row["command"] == "echo [REDACTED_AWS] --after"


@pytest.mark.parametrize("split", [" ", "\t", "\n", "\u2028", "\u2029"],
                         ids=["space", "tab", "lf", "line-separator", "paragraph-separator"])
def test_gate_log_keeps_keys_split_by_retained_separators(tmp_path: Path, split: str):
    (tmp_path / ".aegis").mkdir()
    command = f"echo {_KEY_PREFIX}{split}{_KEY_BODY} --after\x1b[0m"

    log_gate_event(command, "allow", "", tmp_path)

    (row,) = _rows(tmp_path)
    # ROUND-1g ruling: the trailing CSI is not stored, and "after" at that cut is withheld by the existing marker.
    assert row["command"] == f"echo {_KEY_PREFIX}{split}{_KEY_BODY} --..."
    assert "\x1b" not in row["command"]


def test_gate_log_preserves_ordinary_record_bytes_and_order(tmp_path: Path):
    (tmp_path / ".aegis").mkdir()
    command = "  echo  plain\tvalue\r\x1b[31mnext " + "x" * 300

    log_gate_event(command, "deny", "fixed reason", tmp_path)
    log_gate_event("ls", "allow", "", tmp_path)

    deny, allow = _rows(tmp_path)
    # ROUND-1g ruling: stored text ends at the first ESC, and "value" at that cut is withheld by the existing marker.
    expected = [
        {"timestamp": deny["timestamp"], "command": "  echo  plain\t...", "decision": "deny", "reason": "fixed reason"},
        {"timestamp": allow["timestamp"], "command": "ls", "decision": "allow"},
    ]
    path = tmp_path / ".aegis" / "state" / "gate_events.jsonl"
    assert path.read_bytes() == b"".join(
        (json.dumps(row, ensure_ascii=True, separators=(",", ":")) + "\n").encode("ascii")
        for row in expected
    )


@pytest.mark.parametrize("command", [
    "A" * 5000 + "\r",
    "echo " + "x" * 5000 + "\r",
    "echo " + "A" * 5000 + "\x1b[31m",
    "echo \x1b[31m" + "A" * 5000,
], ids=["bare-cr", "echo-cr", "late-csi", "early-csi"])
def test_gate_log_preserves_the_prefix_of_long_ordinary_commands(tmp_path: Path, command: str):
    (tmp_path / ".aegis").mkdir()

    log_gate_event(command, "allow", "", tmp_path)

    (row,) = _rows(tmp_path)
    # ROUND-1e ruling: a command longer than 4096 characters is stored only up to its first ESC or C1.
    if command == "echo \x1b[31m" + "A" * 5000:
        assert row["command"] == "echo "
    else:
        assert row["command"] == command[:200]


def test_gate_log_withholds_a_key_that_crosses_the_detection_bound(tmp_path: Path):
    (tmp_path / ".aegis").mkdir()
    prefix = "echo label="
    command = f"{prefix}{_KEY_PREFIX}{_KEY_BODY[:8]}\x1b[" + "7" * 5000 + f"m{_KEY_BODY[8:]}"

    log_gate_event(command, "allow", "", tmp_path)

    (row,) = _rows(tmp_path)
    assert row["command"] == prefix + "..."


@pytest.mark.parametrize("command", [
    "echo https://localhost:8080?q=" + "x" * 5000 + "\r",
    "echo eyJ" + "a" * 5000 + "\r",
    "echo -----BEGIN bogus" + "x" * 5000 + "\r",
    "curl http://localhost:8000?" + "a" * 5000 + "\r",
    "curl http://localhost:8000#" + "a" * 5000 + "\x1b[31m",
], ids=["url-query", "jwt-no-delimiters", "bogus-pem-label", "url-password-cap-query", "url-password-cap-fragment"])
def test_gate_log_keeps_long_near_matches(tmp_path: Path, command: str):
    (tmp_path / ".aegis").mkdir()

    log_gate_event(command, "allow", "", tmp_path)

    (row,) = _rows(tmp_path)
    assert row["command"] == command[:200]


@pytest.mark.parametrize("before,after", [
    ("password='ABC", "DEF'"),
    ('token="ABC', 'DEF"'),
    ("password is 'Q7m9X", "r8Z'"),
    ('password is "Q7m9X', 'r8Z"'),
    ("Authorization: Basic ABC", "DEF"),
    ("Authorization: Digest ABC", "DEF"),
    ("Authorization: Token ABC", "DEF"),
    ("Authorization: Negotiate ABC", "DEF"),
], ids=["single-assignment", "double-assignment", "single-prose", "double-prose",
        "basic", "digest", "token", "negotiate"])
def test_gate_log_withholds_crossing_credential_fragments(tmp_path: Path, before: str, after: str):
    (tmp_path / ".aegis").mkdir()

    log_gate_event(f"echo {before}" + "\r" * 5000 + after, "allow", "", tmp_path)

    (row,) = _rows(tmp_path)
    assert row["command"] == "echo ..."


@pytest.mark.parametrize("escape", ["\x1bc", "\x1b7", "\x1b]0;title\x07", "\x1bPdata\x1b\\"],
                         ids=["esc-c", "esc-7", "closed-osc", "closed-dcs"])
def test_gate_log_withholds_canonical_key_before_a_crossing_csi(tmp_path: Path, escape: str):
    (tmp_path / ".aegis").mkdir()
    head = f"echo {_KEY_PREFIX}{_KEY_BODY[:4]}{escape}{_KEY_BODY[4:8]}"
    command = head + "\x1b[" + "7" * 5000 + "m" + _KEY_BODY[8:]

    log_gate_event(command, "allow", "", tmp_path)

    (row,) = _rows(tmp_path)
    assert row["command"] == "echo ..."


@pytest.mark.parametrize("introducer,terminator", [("\x1b]0;", "\x07"), ("\x1bP", "\x1b\\")],
                         ids=["osc", "dcs"])
def test_gate_log_withholds_a_key_before_a_crossing_control_string(tmp_path: Path, introducer: str, terminator: str):
    (tmp_path / ".aegis").mkdir()
    command = f"echo {_KEY_PREFIX}{_KEY_BODY[:8]}{introducer}" + "a" * 5000 + terminator + _KEY_BODY[8:]

    log_gate_event(command, "allow", "", tmp_path)

    (row,) = _rows(tmp_path)
    assert row["command"] == "echo ..."


@pytest.mark.parametrize("prefix", ["", "1", "a" * 33], ids=["bare", "invalid-scheme", "oversized-scheme"])
def test_gate_log_withholds_crossing_bare_url_userinfo(tmp_path: Path, prefix: str):
    (tmp_path / ".aegis").mkdir()
    command = f"echo {prefix}://user:SUPER_SECRET_PASSWORD" + "\r" * 5000 + "@host"

    log_gate_event(command, "allow", "", tmp_path)

    (row,) = _rows(tmp_path)
    assert row["command"] == f"echo {prefix}..."


@pytest.mark.parametrize("intro,terminator,payload", [
    ("\x1b]0;", "\x07", _KEY_PREFIX + _KEY_BODY[:4]),
    ("\x1bP", "\x07", _KEY_PREFIX + _KEY_BODY[:4]),
    ("\x1b]0;", "\x1b\\", "://user:abc"),
    ("\x1bP", "\x1b\\", "://user:abc"),
    ("\x1b", "", "7"),
    ("\x1b", "", "c"),
], ids=["osc-bel", "dcs-bel", "osc-st", "dcs-st", "esc-7", "esc-c"])
def test_gate_log_keeps_a_sealed_control_string(tmp_path: Path, intro: str, terminator: str, payload: str):
    (tmp_path / ".aegis").mkdir()
    command = f"echo {intro}{payload}{terminator}" + "\r" * 5000

    log_gate_event(command, "allow", "", tmp_path)

    (row,) = _rows(tmp_path)
    # ROUND-1e ruling: a command longer than 4096 characters is stored only up to its first ESC or C1.
    assert row["command"] == "echo "


def _escape_finals(text: str) -> str:
    return "".join("\x1b[0" + char for char in text)


def test_gate_log_stores_only_text_before_escape_encoded_key_finals(tmp_path: Path):
    (tmp_path / ".aegis").mkdir()
    command = "echo " + _escape_finals(_KEY_PREFIX + "M" * 8) + "\r" * 5000 + "M" * 8

    log_gate_event(command, "allow", "", tmp_path)

    (row,) = _rows(tmp_path)
    assert row["command"] == "echo "
    assert "\x1b" not in row["command"]


@pytest.mark.parametrize("command,secret", [
    ("echo ://user:SUPER_SECRET_PASSWORD" + "\x1b[" + "9" * 5000 + "m@host", "SUPER_SECRET_PASSWORD"),
    ("echo " + _KEY_PREFIX + _KEY_BODY[:8] + "\x1b[" + "9" * 5000 + "m" + _KEY_BODY[8:], _KEY_PREFIX),
    ("echo " + _KEY_PREFIX + _KEY_BODY[:8] + "\x9b" + ";" * 5000 + "m" + _KEY_BODY[8:], _KEY_PREFIX),
    ("echo \x1b]" + _KEY_PREFIX + _KEY_BODY[:8] + "\x1b[" + "9" * 5000 + "m" + _KEY_BODY[8:], _KEY_PREFIX),
], ids=["userinfo-csi", "akia-csi", "akia-c1-csi", "akia-after-unclosed-osc"])
def test_gate_log_withholds_secret_heads_before_an_open_escape(tmp_path: Path, command: str, secret: str):
    (tmp_path / ".aegis").mkdir()

    log_gate_event(command, "allow", "", tmp_path)

    (row,) = _rows(tmp_path)
    assert secret not in row["command"]
    assert "\x1b" not in row["command"]
    assert "\x9b" not in row["command"]


def test_gate_log_escape_cut_fails_closed_then_retries(tmp_path: Path, monkeypatch):
    (tmp_path / ".aegis").mkdir()
    command = "echo " + _escape_finals(_KEY_PREFIX + "M" * 8) + "\r" * 5000 + "M" * 8
    expected = run_safety_gate(cmd=command, workspace=tmp_path)
    unsupported = (re.compile(r"ab(?=c)"), "REDACTED", "[REDACTED]")
    rules = redaction_patterns.SECRET_REDACTIONS

    monkeypatch.setattr(redaction_patterns, "SECRET_REDACTIONS", (*rules, unsupported))
    assert run_safety_gate(cmd=command, workspace=tmp_path) == expected

    monkeypatch.setattr(redaction_patterns, "SECRET_REDACTIONS", rules)
    assert run_safety_gate(cmd=command, workspace=tmp_path) == expected
    assert [row["command"] for row in _rows(tmp_path)] == ["echo ", "", "echo "]


def test_gate_log_cuts_each_concurrent_long_escape_command(tmp_path: Path):
    workspaces = [tmp_path / "first", tmp_path / "second"]
    for workspace in workspaces:
        (workspace / ".aegis").mkdir(parents=True)
    commands = [
        "echo " + _escape_finals(_KEY_PREFIX + "M" * 8) + "\r" * 5000 + "M" * 8,
        "echo ://user:SUPER_SECRET_PASSWORD" + "\x1b[" + "9" * 5000 + "m@host",
    ]
    ready = Barrier(len(commands), timeout=5)

    def append(workspace, command):
        ready.wait()
        log_gate_event(command, "allow", "", workspace)

    with ThreadPoolExecutor(max_workers=len(commands)) as pool:
        list(pool.map(append, workspaces, commands))

    stored = [[row["command"] for row in _rows(workspace)] for workspace in workspaces]
    assert _KEY_PREFIX not in stored[0][0]
    assert "SUPER_SECRET_PASSWORD" not in stored[1][0]
    assert stored[0] == ["echo "]
    assert "\x1b" not in stored[1][0]


@pytest.mark.parametrize("intro", ["\x1b]", "\x1bP"], ids=["osc", "dcs"])
@pytest.mark.parametrize("csi,parameter", [("\x1b[", "7"), ("\x9b", ";")], ids=["esc-csi", "c1-csi"])
def test_gate_log_withholds_crossing_key_after_an_unclosed_string(tmp_path: Path, intro: str, csi: str, parameter: str):
    (tmp_path / ".aegis").mkdir()
    prefix = f"echo {intro} "
    command = f"{prefix}{_KEY_PREFIX}{_KEY_BODY[:8]}{csi}" + parameter * 5000 + "m" + _KEY_BODY[8:]

    log_gate_event(command, "allow", "", tmp_path)

    (row,) = _rows(tmp_path)
    # ROUND-1e ruling: a command longer than 4096 characters is stored only up to its first ESC or C1.
    assert row["command"] == "echo "
    assert _KEY_PREFIX not in row["command"]


@pytest.mark.parametrize("head,tail", [
    ("tok\x1b>en\x1b='ab=", "cdef'"),
    ("tok\x1b>en\x1b='!@#", "$%^'"),
    ("se\x1bcret i\x1b>s 'Q7m9!", "r8Z'"),
    ("Authorizatio\x1b>n: Basi\x1bc ab=", "cdef"),
], ids=["assignment", "assignment-punctuation", "prose", "authorization"])
def test_gate_log_withholds_crossing_credential_in_attribution_view(tmp_path: Path, head: str, tail: str):
    (tmp_path / ".aegis").mkdir()

    log_gate_event("echo " + head + "\r" * 5000 + tail, "allow", "", tmp_path)

    (row,) = _rows(tmp_path)
    # ROUND-1e ruling: a command longer than 4096 characters is stored only up to its first ESC or C1.
    if head == "tok\x1b>en\x1b='ab=":
        assert row["command"] == "echo .."
        assert "ab=" not in row["command"]
    elif head == "tok\x1b>en\x1b='!@#":
        assert row["command"] == "echo .."
        assert "!@#" not in row["command"]
    elif head == "se\x1bcret i\x1b>s 'Q7m9!":
        assert row["command"] == "echo ."
        assert "se" not in row["command"]
        assert "Q7m9" not in row["command"]
    else:
        assert row["command"] == "echo ..."


def test_gate_log_discards_impossible_scheme_lookaheads_in_attribution(tmp_path: Path):
    (tmp_path / ".aegis").mkdir()
    command = "echo tok\x1b>en\x1b='ab=" + "\x1b7\x1bN\x1bM\x1bO" * 8 + "\r" * 5000 + "foo'"

    log_gate_event(command, "allow", "", tmp_path)

    (row,) = _rows(tmp_path)
    # ROUND-1e ruling: _prefix_checks is deleted, so the stored command is the measured clip and the credential is absent.
    assert row["command"] == "echo .."
    assert "ab=" not in row["command"]


def test_gate_log_withholds_command_when_prefix_derivation_fails(tmp_path: Path, monkeypatch):
    (tmp_path / ".aegis").mkdir()
    command = "echo " + "A" * 5000 + "\r"
    expected = run_safety_gate(cmd=command, workspace=tmp_path)
    unsupported = (re.compile(r"ab(?=c)"), "REDACTED", "[REDACTED]")
    rules = redaction_patterns.SECRET_REDACTIONS

    monkeypatch.setattr(redaction_patterns, "SECRET_REDACTIONS", (*rules, unsupported))
    assert run_safety_gate(cmd=command, workspace=tmp_path) == expected

    monkeypatch.setattr(redaction_patterns, "SECRET_REDACTIONS", rules)
    assert run_safety_gate(cmd=command, workspace=tmp_path) == expected
    assert [row["command"] for row in _rows(tmp_path)] == [command[:200], "", command[:200]]


def test_gate_log_searches_each_cutoff_pattern_once_when_views_agree(tmp_path: Path):
    (tmp_path / ".aegis").mkdir()
    head = "echo " + "eyJ-" * 1022 + "xx!"
    command = head + "x" * 1000 + "\r"
    searches = []

    def count_search(frame, event, method):
        if (event != "c_call" or not isinstance(getattr(method, "__self__", None), re.Pattern)
                or method.__name__ not in ("search", "finditer")):
            return
        width = frame.f_locals.get("end", len(head)) - frame.f_locals.get("left", 0)
        while frame is not None:
            if frame.f_code.co_name == "bound_redaction_spans":
                searches.append((method.__self__, width))
                return
            frame = frame.f_back

    previous = sys.getprofile()
    sys.setprofile(count_search)
    try:
        log_gate_event(command, "allow", "", tmp_path)
    finally:
        sys.setprofile(previous)

    (row,) = _rows(tmp_path)
    assert row["command"] == command[:200]
    assert searches and len(searches) == len({pattern for pattern, _ in searches})
    # Only the PEM label has an unbounded width. All other rows must restrict
    # their probes to the suffix where a proper prefix can fit.
    assert sum(width == len(head) for _, width in searches) == 1


def test_safety_gate_logs_an_empty_command_for_non_string_payload(tmp_path: Path):
    (tmp_path / ".aegis").mkdir()
    reason = "Unable to parse command — requesting confirmation"

    result = run_safety_gate(payload={"toolCall": {"args": {"CommandLine": 1}}}, workspace=tmp_path)

    assert result == (0, {"decision": "force_ask", "reason": f"🛡️ Safety Gate: {reason}"})
    (row,) = _rows(tmp_path)
    assert (row["command"], row["decision"], row["reason"]) == ("", "BLOCKED", reason)


def test_gate_log_masks_a_split_key_that_extends_past_the_log_limit(tmp_path: Path):
    (tmp_path / ".aegis").mkdir()
    before = "x" * 179 + " "
    split_key = f"{_KEY_PREFIX}{_KEY_BODY[:8]}\x1b[31m{_KEY_BODY[8:]}"

    log_gate_event(before + split_key + " --after", "allow", "", tmp_path)

    (row,) = _rows(tmp_path)
    # ROUND-1g ruling: the CSI ends the stored command and the key head at that cut is withheld.
    assert row["command"] == before + "..."
    assert _KEY_BODY not in row["command"]


def test_gate_log_does_not_expose_later_controls_when_a_long_secret_is_shortened(tmp_path: Path):
    (tmp_path / ".aegis").mkdir()
    pem = "-----BEGIN " + "PRIVATE KEY-----\n" + "x" * 8192 + "\n-----END PRIVATE KEY-----"
    command = f"echo {pem} {_KEY_PREFIX}\r{_KEY_BODY}"

    log_gate_event(command, "allow", "", tmp_path)

    (row,) = _rows(tmp_path)
    assert row["command"] == "echo "


def test_gate_log_retries_after_a_storage_failure_without_echoing_the_key(tmp_path: Path, capsys):
    aegis = tmp_path / ".aegis"
    aegis.mkdir()
    state = aegis / "state"
    state.write_bytes(b"obstruction")
    command = f"echo {_KEY_PREFIX}\r{_KEY_BODY}"

    log_gate_event(command, "deny", "fixed reason", tmp_path)
    assert state.read_bytes() == b"obstruction"
    assert capsys.readouterr() == ("", "")

    state.unlink()
    log_gate_event(command, "deny", "fixed reason", tmp_path)

    (row,) = _rows(tmp_path)
    assert row["command"] == "echo [REDACTED_AWS]"


def test_gate_log_masks_each_concurrent_append(tmp_path: Path):
    workspaces = [tmp_path / "first", tmp_path / "second"]
    for workspace in workspaces:
        (workspace / ".aegis").mkdir(parents=True)
    commands = [
        f"echo {_KEY_PREFIX}\0{_KEY_BODY} --first",
        f"echo {_KEY_PREFIX}\x1b[31m{_KEY_BODY} --second",
    ]
    ready = Barrier(len(commands), timeout=5)

    def append(workspace, command):
        ready.wait()
        log_gate_event(command, "allow", "", workspace)

    with ThreadPoolExecutor(max_workers=len(commands)) as pool:
        list(pool.map(append, workspaces, commands))

    # ROUND-1g ruling: the short CSI command is stored only up to that ESC, so its key head is withheld.
    assert [[row["command"] for row in _rows(workspace)] for workspace in workspaces] == [
        ["echo [REDACTED_AWS] --first"],
        ["echo ..."],
    ]


def _closed_pem(count: int) -> str:
    return "-----BEGIN " + "PRIVATE KEY-----\n" + ("x" * count) + "\n-----END " + "PRIVATE KEY-----"


def _pem_cut(suffix: str, completion: str) -> str:
    """Closed PEM sized so the 4096 head ends with suffix and completion stays past the cut."""
    opening = "-----BEGIN " + "PRIVATE KEY-----\n"
    closing = "\n-----END " + "PRIVATE KEY-----"
    count = 4096 - len("echo ") - len(opening) - len(closing) - len(suffix)
    return "echo " + _closed_pem(count) + suffix + completion


def _raw_view_cases():
    """Reviewers' raw-view leaks: the separator exists only in the original command."""
    bearer = "echo " + _closed_pem(4014) + " Bearer\r" + ("~" * 16)
    prose = "echo " + _closed_pem(4018) + " password\ris\r'!@#$%^'"
    quoted = "echo " + _closed_pem(4018) + ' password\ris\r"!@#$%^"'
    first = "echo ://\x07:Q7!#$\x1b[31mTAIL@host " + ("x" * 5000)
    cases = [
        ("bearer-cr", bearer, ("Bearer", "~")),
        ("bearer-vt", _pem_cut(" Bearer\v" + ("~" * 15), "~"), ("Bearer", "~")),
        ("bearer-ff", _pem_cut(" Bearer\f" + ("~" * 15), "~"), ("Bearer", "~")),
        ("prose-cr", prose, ("password", "!@#$")),
        ("prose-double", quoted, ("password", "!@#$")),
        ("prose-unquoted", _pem_cut(" password\ris\r!@#$%", "x"), ("password", "!@#$")),
        ("prose-vt", _pem_cut(" password\vis\v'!@#$%", "^'"), ("password", "!@#$")),
        ("prose-ff", _pem_cut(" password\fis\f'!@#$%", "^'"), ("password", "!@#$")),
        ("prose-passwd", _pem_cut(" passwd\ris\r'!@#$%", "^'"), ("passwd", "!@#$")),
        ("prose-pwd", _pem_cut(" pwd\ris\r'!@#$%", "^'"), ("pwd", "!@#$")),
        ("prose-secret", _pem_cut(" secret\ris\r'!@#$%", "^'"), ("secret", "!@#$")),
        ("prose-token", _pem_cut(" token\ris\r'!@#$%", "^'"), ("token", "!@#$")),
        ("prose-api-key", _pem_cut(" api key\ris\r'!@#$%", "^'"), ("api key", "!@#$")),
        ("prose-private-key", _pem_cut(" private key\ris\r'!@#$%", "^'"), ("private key", "!@#$")),
        ("first-escape", first, ("Q7!#$",)),
    ]
    for scheme in ("Basic", "Digest", "Token", "Negotiate"):
        for sep, label in (("\r", "cr"), ("\v", "vt"), ("\f", "ff")):
            command = _pem_cut(" Authorization: " + scheme + sep + "!@#", "wxyz")
            cases.append(("auth-" + scheme.lower() + "-" + label, command, ("!@#",)))
    return cases


@pytest.mark.parametrize("command,fragments", [(case[1], case[2]) for case in _raw_view_cases()],
                         ids=[case[0] for case in _raw_view_cases()])
def test_gate_log_withholds_raw_view_credentials_at_the_cut(tmp_path: Path, command: str, fragments: tuple):
    # ROUND-1f: a raw-view proper prefix across the cut is withheld, so the stored excerpt has no credential.
    (tmp_path / ".aegis").mkdir()
    assert len(command) > 4096
    for fragment in fragments:
        assert fragment in command

    log_gate_event(command, "allow", "", tmp_path)

    (row,) = _rows(tmp_path)
    for fragment in fragments:
        assert fragment not in row["command"]
    if command.startswith("echo ://"):
        assert "\x1b" not in row["command"]
        assert "\x07" not in row["command"]
    else:
        assert "[REDACTED_PEM]" in row["command"]


def test_gate_log_raw_view_cutoff_fails_closed_then_retries(tmp_path: Path, monkeypatch):
    (tmp_path / ".aegis").mkdir()
    command = "echo " + _closed_pem(4014) + " Bearer\r" + ("~" * 16)
    expected = run_safety_gate(cmd=command, workspace=tmp_path)
    unsupported = (re.compile(r"ab(?=c)"), "REDACTED", "[REDACTED]")
    rules = redaction_patterns.SECRET_REDACTIONS

    monkeypatch.setattr(redaction_patterns, "SECRET_REDACTIONS", (*rules, unsupported))
    assert run_safety_gate(cmd=command, workspace=tmp_path) == expected

    monkeypatch.setattr(redaction_patterns, "SECRET_REDACTIONS", rules)
    assert run_safety_gate(cmd=command, workspace=tmp_path) == expected
    stored = [row["command"] for row in _rows(tmp_path)]
    assert stored[1] == ""
    assert all("Bearer" not in text and "~" not in text for text in stored)
    assert "[REDACTED_PEM]" in stored[0]
    assert "[REDACTED_PEM]" in stored[2]


def test_gate_log_withholds_each_concurrent_raw_view_credential(tmp_path: Path):
    workspaces = [tmp_path / "first", tmp_path / "second"]
    for workspace in workspaces:
        (workspace / ".aegis").mkdir(parents=True)
    commands = [
        "echo " + _closed_pem(4014) + " Bearer\r" + ("~" * 16),
        "echo " + _closed_pem(4018) + " password\ris\r'!@#$%^'",
    ]
    ready = Barrier(len(commands), timeout=5)

    def append(workspace, command):
        ready.wait()
        log_gate_event(command, "allow", "", workspace)

    with ThreadPoolExecutor(max_workers=len(commands)) as pool:
        list(pool.map(append, workspaces, commands))

    stored = [[row["command"] for row in _rows(workspace)] for workspace in workspaces]
    assert "Bearer" not in stored[0][0] and "~" not in stored[0][0]
    assert "password" not in stored[1][0] and "!@#$" not in stored[1][0]
    assert "[REDACTED_PEM]" in stored[0][0]
    assert "[REDACTED_PEM]" in stored[1][0]


def _sealed_csi_commands():
    """OSC and DCS payloads, ESC and C1 forms, BEL and ST terminators, with a complete CSI inside."""
    rows = []
    for intro, intro_id in (("\x1b]0;", "osc"), ("\x1bP", "dcs"), ("\x9d0;", "c1-osc"), ("\x90", "c1-dcs")):
        for csi, csi_id in (("\x1b[31m", "esc-csi"), ("\x9b31m", "c1-csi")):
            for terminator, term_id in (("\x07", "bel"), ("\x1b\\", "st")):
                command = f"echo {intro}{_KEY_PREFIX}{csi}{_KEY_BODY}{terminator}"
                rows.append((f"{intro_id}-{csi_id}-{term_id}", command))
    return rows


@pytest.mark.parametrize("command", [row[1] for row in _sealed_csi_commands()],
                         ids=[row[0] for row in _sealed_csi_commands()])
def test_gate_log_stores_nothing_after_the_first_escape(tmp_path: Path, command: str):
    # ROUND-1g ruling: every gate command is stored only up to its first ESC or C1.
    (tmp_path / ".aegis").mkdir()
    assert len(command) <= 4096
    assert _KEY_BODY in command

    log_gate_event(command, "allow", "", tmp_path)

    (row,) = _rows(tmp_path)
    assert row["command"] == "echo "
    assert _KEY_PREFIX not in row["command"]
    assert _KEY_BODY not in row["command"]


def test_gate_log_keeps_a_short_command_without_an_escape(tmp_path: Path):
    (tmp_path / ".aegis").mkdir()
    command = "echo plain-value"

    log_gate_event(command, "allow", "", tmp_path)

    (row,) = _rows(tmp_path)
    assert row["command"] == command


def test_gate_log_withholds_a_key_head_before_a_short_escape(tmp_path: Path):
    # ROUND-1g ruling: a prefix that can still match across the first ESC is withheld; the body after it is not stored.
    (tmp_path / ".aegis").mkdir()
    command = f"echo {_KEY_PREFIX}\x1b]0;\x1b[31m{_KEY_BODY}\x07"

    log_gate_event(command, "allow", "", tmp_path)

    (row,) = _rows(tmp_path)
    assert row["command"] == "echo ..."
    assert _KEY_PREFIX not in row["command"]
    assert _KEY_BODY not in row["command"]


def test_gate_log_short_escape_cut_fails_closed_then_retries(tmp_path: Path, monkeypatch):
    (tmp_path / ".aegis").mkdir()
    command = f"echo \x1b]0;{_KEY_PREFIX}{_KEY_BODY}\x07"
    expected = run_safety_gate(cmd=command, workspace=tmp_path)
    unsupported = (re.compile(r"ab(?=c)"), "REDACTED", "[REDACTED]")
    rules = redaction_patterns.SECRET_REDACTIONS

    monkeypatch.setattr(redaction_patterns, "SECRET_REDACTIONS", (*rules, unsupported))
    assert run_safety_gate(cmd=command, workspace=tmp_path) == expected

    monkeypatch.setattr(redaction_patterns, "SECRET_REDACTIONS", rules)
    assert run_safety_gate(cmd=command, workspace=tmp_path) == expected
    stored = [row["command"] for row in _rows(tmp_path)]
    assert stored[1] == ""
    assert all(_KEY_PREFIX not in text and _KEY_BODY not in text for text in stored)
    assert stored[0] == "echo "
    assert stored[2] == "echo "


def test_gate_log_cuts_each_concurrent_short_escape_command(tmp_path: Path):
    workspaces = [tmp_path / "first", tmp_path / "second"]
    for workspace in workspaces:
        (workspace / ".aegis").mkdir(parents=True)
    commands = [
        f"echo \x1b]0;{_KEY_PREFIX}\x1b[31m{_KEY_BODY}\x07",
        f"echo \x1bP{_KEY_PREFIX}\x9b31m{_KEY_BODY}\x1b\\",
    ]
    ready = Barrier(len(commands), timeout=5)

    def append(workspace, command):
        ready.wait()
        log_gate_event(command, "allow", "", workspace)

    with ThreadPoolExecutor(max_workers=len(commands)) as pool:
        list(pool.map(append, workspaces, commands))

    stored = [[row["command"] for row in _rows(workspace)] for workspace in workspaces]
    assert stored == [["echo "], ["echo "]]
    assert all(_KEY_BODY not in text for row in stored for text in row)
