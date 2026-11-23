"""aegis_core.primitives: path containment, strict JSON and UTC timestamps (w11 R-structure-17/20/21)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os
import sys
import time

import pytest

from aegis_core import primitives
from aegis_core.primitives import (
    TS_FORMAT, DuplicateKeyError, is_within, key_within, parse_utc, real_key, real_path, safe_parts, strict_loads,
    utc_stamp,
)

POSIX_ONLY = pytest.mark.skipif(sys.platform == "win32", reason="symlinks and tzset are POSIX here")


@pytest.fixture(autouse=True)
def _fake_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    for key in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(key, str(home))
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(home / ".gitconfig"))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for key in ("CLAUDE_CONFIG_DIR", "CODEX_HOME"):
        monkeypatch.delenv(key, raising=False)


# ── Containment (T17) ────────────────────────────────────────────────────────

@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "ws"
    (root / "a").mkdir(parents=True)
    (root / "a" / "f").write_bytes(b"x")
    out = tmp_path / "out"
    out.mkdir()
    (out / "g").write_bytes(b"y")
    if sys.platform != "win32":
        (root / "link_out").symlink_to(out, target_is_directory=True)
        (root / "loop1").symlink_to(root / "loop2")
        (root / "loop2").symlink_to(root / "loop1")
    return root, out


@pytest.mark.parametrize("unresolvable", [False, True])
def test_inside_paths_are_inside_whichever_way_unresolvable_fails(tree, unresolvable):
    root, _ = tree
    for path in (root / "a" / "f", root, root / "a" / "missing" / "deeper"):
        assert is_within(path, root, unresolvable=unresolvable) is True, path
        assert is_within(str(path), str(root), unresolvable=unresolvable) is True, path


@POSIX_ONLY
@pytest.mark.parametrize("unresolvable", [False, True])
def test_outside_paths_and_links_out_are_outside_whichever_way_unresolvable_fails(tree, unresolvable):
    root, out = tree
    for path in (out / "g", root / "link_out", root / "link_out" / "g", str(root) + os.sep + ".." + os.sep + "out"):
        assert is_within(path, root, unresolvable=unresolvable) is False, path


@POSIX_ONLY
def test_a_final_component_loop_and_a_nul_byte_take_the_callers_polarity(tree):
    root, _ = tree
    for path in (root / "loop1", str(root / "a") + "\0x"):
        assert real_key(path) is None
        assert is_within(path, root, unresolvable=False) is False
        assert is_within(path, root, unresolvable=True) is True
    assert is_within(root / "a", root / "loop1", unresolvable=True) is True


@POSIX_ONLY
def test_root_slash_contains_every_absolute_path():
    assert is_within("/etc/hosts", "/", unresolvable=False) is True
    assert is_within("/etc/hosts", "/", unresolvable=True) is True
    assert key_within("/etc", "/") and key_within("/", "/")


def test_key_within_needs_a_separator_boundary():
    root = os.path.join(os.sep + "ws", "repo")
    assert key_within(root, root)
    assert key_within(os.path.join(root, "x"), root)
    assert key_within(os.path.join(root, "x"), root + os.sep)
    assert not key_within(root + "2", root)
    assert not key_within(os.path.dirname(root), root)


def test_is_within_has_no_default_polarity(tree):
    root, _ = tree
    with pytest.raises(TypeError):
        is_within(root, root)  # type: ignore[call-arg]


def test_real_path_drops_the_windows_extended_length_prefix(monkeypatch):
    monkeypatch.setattr(primitives.os.path, "realpath", lambda p: "\\\\?\\C:\\x")
    assert real_path("anything") == "C:\\x"
    monkeypatch.setattr(primitives.os.path, "realpath", lambda p: "\\\\?\\UNC\\srv\\sh")
    assert real_path("anything") == "\\\\srv\\sh"


def test_real_key_folds_case_where_the_platform_does(monkeypatch):
    monkeypatch.setattr(primitives.os.path, "realpath", lambda p: p)
    monkeypatch.setattr(primitives.os.path, "islink", lambda p: False)
    monkeypatch.setattr(primitives.os.path, "normcase", str.lower)
    assert real_key("C:\\X") == real_key("c:\\x") == "c:\\x"


def test_real_key_answers_none_when_resolving_raises(monkeypatch):
    def boom(path):
        raise OSError("no")

    monkeypatch.setattr(primitives.os.path, "realpath", boom)
    assert real_key("x") is None
    assert is_within("x", "y", unresolvable=True) is True
    assert is_within("x", "y", unresolvable=False) is False


@pytest.mark.parametrize("rel", ["", "/x", ".", "..", "a//b", "a/./b", "a/../b", "a/", None, 7, b"a"])
def test_safe_parts_refuses_paths_that_leave_or_name_nothing(rel):
    assert safe_parts(rel, windows=False) is None
    assert safe_parts(rel, windows=True) is None


def test_safe_parts_keeps_posix_file_names_posix_allows():
    assert safe_parts("src/x.py") == ("src", "x.py")
    assert safe_parts("src/x.py", windows=True) == ("src", "x.py")
    assert safe_parts("a:b.py", windows=False) == ("a:b.py",)
    assert safe_parts("a\\b.py", windows=False) == ("a\\b.py",)


@pytest.mark.parametrize("rel", ["D:evil.py", "C:x", "a\\..\\..\\b", "x:stream", "a\\b.py", "dir/f:alt"])
def test_safe_parts_for_windows_refuses_drives_streams_and_backslashes(rel):
    assert safe_parts(rel, windows=True) is None


# ── Strict JSON (T21) ────────────────────────────────────────────────────────

@pytest.mark.parametrize("text", ['{"a":1e999}', '{"a":-1e999}', '{"a":NaN}', '{"a":-Infinity}', '[Infinity]'])
def test_strict_loads_refuses_numbers_json_cannot_hold(text):
    with pytest.raises(ValueError) as caught:
        strict_loads(text)
    assert not isinstance(caught.value, DuplicateKeyError)
    assert str(caught.value).endswith("is not allowed")


def test_the_refusal_messages_are_the_ones_readers_echo():
    with pytest.raises(ValueError, match=r"\ANaN is not allowed\Z"):
        strict_loads('{"a":NaN}')
    with pytest.raises(ValueError) as caught:
        strict_loads('{"a":' + "9" * 5000 + "e999}")
    assert len(str(caught.value)) < 60


@pytest.mark.parametrize("text", ['{"a":1,"a":2}', '{"x":{"a":1,"a":2}}'])
def test_strict_loads_refuses_a_duplicate_key(text):
    with pytest.raises(DuplicateKeyError, match=r"\Aduplicate key 'a'\Z"):
        strict_loads(text)
    assert issubclass(DuplicateKeyError, ValueError)


@pytest.mark.parametrize("text, value", [
    ('{"a":1e308}', {"a": 1e308}),
    ('{"a":-0.0}', {"a": -0.0}),
    ('{"a":1e-999}', {"a": 0.0}),
    ('{"a":1000000000000000000000000000000}', {"a": 10 ** 30}),
    (b'{"a":[1,2.5]}', {"a": [1, 2.5]}),
])
def test_strict_loads_reads_finite_json(text, value):
    assert strict_loads(text) == value


def test_strict_loads_lets_recursion_error_through():
    with pytest.raises(RecursionError):
        strict_loads("[" * 100000)


# ── UTC timestamps (T20) ─────────────────────────────────────────────────────

NAIVE = datetime(2026, 10, 19, 12, 0)


@pytest.fixture(params=["America/New_York", "Asia/Tokyo"])
def zone(request):
    if sys.platform == "win32":
        pytest.skip("time.tzset is POSIX")
    old = os.environ.get("TZ")
    os.environ["TZ"] = request.param
    time.tzset()
    yield request.param
    if old is None:
        os.environ.pop("TZ", None)
    else:
        os.environ["TZ"] = old
    time.tzset()


def test_a_naive_datetime_is_utc_in_every_time_zone(zone):
    assert utc_stamp(NAIVE) == "2026-10-19T12:00:00Z"


def test_aware_datetimes_and_posix_times_are_converted_to_utc():
    assert utc_stamp(datetime(2026, 10, 19, 14, 0, tzinfo=timezone(timedelta(hours=2)))) == "2026-10-19T12:00:00Z"
    assert utc_stamp(0) == "1970-01-01T00:00:00Z"
    assert utc_stamp(1792442143.9) == datetime.fromtimestamp(1792442143, timezone.utc).strftime(TS_FORMAT)


def test_now_is_stamped_in_utc():
    before = datetime.now(timezone.utc).replace(microsecond=0)
    stamp = utc_stamp()
    after = datetime.now(timezone.utc)
    moment = datetime.strptime(stamp, TS_FORMAT).replace(tzinfo=timezone.utc)
    assert before <= moment <= after


@pytest.mark.parametrize("moment", [True, "2026-01-01", object()])
def test_utc_stamp_refuses_what_is_not_a_moment(moment):
    with pytest.raises(TypeError):
        utc_stamp(moment)


@pytest.mark.parametrize("value", [
    "2026-10-19T12:00:00Z", "2026-10-19T12:00:00z", "2026-10-19t12:00:00Z",
    "\uff12\uff10\uff12\uff16-10-19T12:00:00Z",
])
def test_strict_parse_reads_what_strptime_reads(value):
    assert parse_utc(value) == datetime(2026, 10, 19, 12, 0, tzinfo=timezone.utc)


@pytest.mark.parametrize("value", [
    "2026-10-19T12:00:00.5Z", "2026-10-19T12:00:00+00:00", " 2026-10-19T12:00:00Z", "2026-10-19T12:00:00Z\n",
    "", None, 7, "2026-13-45T00:00:00Z", "2026-02-30T00:00:00Z", "2026-10-19T12:00:60Z",
])
def test_strict_parse_refuses_everything_else(value):
    assert parse_utc(value) is None


@pytest.mark.parametrize("value", ["2026-10-19T14:00:00+02:00", "2026-10-19T12:00:00.123Z", "2026-10-19T12:00:00"])
def test_lenient_parse_reads_offsets_fractions_and_naive_as_utc(value):
    parsed = parse_utc(value, lenient=True)
    assert parsed is not None and parsed.utcoffset() == timedelta(0)
    assert parsed.replace(microsecond=0) == datetime(2026, 10, 19, 12, 0, tzinfo=timezone.utc)


@pytest.mark.parametrize("value", ["", None, "yesterday", "2026-13-45T00:00:00Z", 1.5])
def test_lenient_parse_refuses_what_is_not_a_time(value):
    assert parse_utc(value, lenient=True) is None


def test_stamps_round_trip():
    assert parse_utc(utc_stamp(datetime(2026, 10, 19, 12, 0))) == datetime(2026, 10, 19, 12, 0, tzinfo=timezone.utc)


# ── Migrated containment sites (T17-e, T17-g, T17-h) ──────────────────────────

@POSIX_ONLY
@pytest.mark.skipif(not os.path.isfile("/etc/hosts"), reason="needs /etc/hosts")
def test_verify_keeps_a_named_file_of_a_repository_at_the_filesystem_root(monkeypatch, capsys):
    import argparse

    from aegis_cli import verify

    monkeypatch.setattr(verify, "_resolve_git_cwd", lambda args: "/")
    assert verify.resolve_target_files(argparse.Namespace(files=["etc/hosts"])) == ["etc/hosts"]
    assert "out-of-tree" not in capsys.readouterr().err


def test_verify_still_skips_a_named_file_outside_the_repository(tmp_path, monkeypatch, capsys):
    import argparse

    from aegis_cli import verify

    (tmp_path / "repo").mkdir()
    (tmp_path / "secret.txt").write_bytes(b"x")
    monkeypatch.setattr(verify, "_resolve_git_cwd", lambda args: str(tmp_path / "repo"))
    assert verify.resolve_target_files(argparse.Namespace(files=["../secret.txt"])) == []
    assert "skipping out-of-tree file" in capsys.readouterr().err


def test_a_baseline_finding_named_with_a_colon_reads_on_every_platform():
    from aegis_core import baseline

    entry = {"rule": "trap-x", "path": "a:b.py", "fp": "0" * 64}
    data = ('{"v": 1, "findings": [%s]}' % str(entry).replace("'", '"')).encode("utf-8")
    assert {e.path for e in baseline.parse(data)} == {"a:b.py"}
    with pytest.raises(baseline.BaselineFileError):
        baseline.parse(data.replace(b"a:b.py", b"a/../b.py"))


@pytest.mark.parametrize("path", ["a:b", "a\\b", "../x", "/x", "", "a/./b"])
def test_a_benchmark_corpus_path_follows_the_windows_rule_on_every_platform(path):
    from aegis_core import benchmark

    with pytest.raises(benchmark.BenchmarkError):
        benchmark._check_corpus_path(path)
    benchmark._check_corpus_path("src/x.py")


def _registry(home, *roots):
    import json

    from aegis_core.workspace.layout import UserLayout

    path = UserLayout(home).workspaces_file
    path.parent.mkdir(parents=True, exist_ok=True)
    entries = [{"root": r, "added_at": "2026-10-19T12:00:00Z", "added_by": "aegis init", "hosts": []} for r in roots]
    path.write_bytes(json.dumps({"v": 1, "workspaces": entries}, indent=2).encode("utf-8") + b"\n")
    return path


def test_a_root_that_cannot_be_resolved_matches_no_registry_entry_and_removes_nothing(tmp_path):
    """None-key trap: a skipped (relative) entry and an unresolvable root both have no key; they
    must not match, or the unrelated entry would be found or removed."""
    from aegis_cli import install_hosts as ih

    home = tmp_path / "home"
    path = _registry(home, "relative/root", str(tmp_path / "ws"))
    before = path.read_bytes()
    unresolvable = str(tmp_path / "x") + "\0y"
    assert ih.find_workspace(ih.read_registry(home), unresolvable) is None
    status, remaining = ih.unregister_workspace(home, unresolvable)
    assert status == "absent" and len(remaining) == 2
    assert path.read_bytes() == before
    with pytest.raises(ih.InstallError, match="cannot be resolved"):
        ih.register_workspace(home, unresolvable, ["claude-code"])
    assert path.read_bytes() == before
    assert ih.is_denied_root(unresolvable, home) is True


# ── Strict JSON readers (T21-d) ──────────────────────────────────────────────

_OVERFLOW = b'{"v": 1, "n": 1e999}'


def test_every_strict_reader_refuses_an_overflowing_number_with_its_own_error(tmp_path):
    from aegis_cli import doctor, doctor_base, install_hosts
    from aegis_core import baseline, packs, team

    assert doctor.SCHEMA

    with pytest.raises(baseline.BaselineFileError, match="not valid JSON"):
        baseline.parse(b'{"v": 1, "findings": [], "x": 1e999}')
    with pytest.raises(team.TeamFileError, match="not valid JSON"):
        team.parse_team(b'{"v": 1, "shared": [], "x": -1e999}')
    with pytest.raises(team.LeaseFormatError, match="not a JSON lease"):
        team.parse_lease(_OVERFLOW, "lane", "0" * 40)
    with pytest.raises(packs.PackError) as caught:
        packs.load_pack(b'{"v": 1, "rules": [], "sha256": 1e999}')
    assert str(caught.value) == "the pack is not valid JSON: 1e999 is not allowed"
    host = tmp_path / "mcp.json"
    host.write_bytes(b'{"mcpServers": {}, "n": 1e999}')
    with pytest.raises(install_hosts.InstallError, match="cannot be written back as JSON"):
        install_hosts._load_json_object(host)
    entry = doctor_base._parse_json(doctor_base._File(host, raw=host.read_bytes()))
    assert entry.error == "is not valid JSON (1e999 is not allowed)" and entry.data is None


@pytest.mark.parametrize("raw", [_OVERFLOW, b'{"v": 1, "v": 1}', b'{"v": NaN}'], ids=["overflow", "duplicate", "nan"])
def test_the_config_files_are_read_strictly(tmp_path, raw):
    from aegis_core import config
    from aegis_core.workspace.layout import UserLayout

    ws = tmp_path / "ws"
    (ws / ".aegis").mkdir(parents=True)
    (ws / ".aegis" / "config.json").write_bytes(raw)
    with pytest.raises(config.ConfigError, match=r"\.aegis/config\.json is not valid JSON"):
        config.RepoConfig.load(ws)
    home = tmp_path / "home"
    (home / ".aegis").mkdir(parents=True, exist_ok=True)
    (home / ".aegis" / "config.json").write_bytes(raw)
    with pytest.raises(config.ConfigError, match="not valid JSON"):
        config.UserConfig.load(None, UserLayout(home))
    assert config.read_user_config(user=UserLayout(home)) is None


# ── Stamps at the sites (T20, AC-5) ──────────────────────────────────────────

def test_a_naive_now_is_utc_in_the_compliance_report(tmp_path, zone):
    from aegis_core import scan_compliance

    assert scan_compliance.report(tmp_path, now=NAIVE)["checked_at"] == "2026-10-19T12:00:00Z"


def test_the_baseline_envelope_keeps_its_posix_time_and_its_own_stamp_is_gone():
    from aegis_core import baseline, primitives

    assert primitives.envelope("s", {}, now=0)["checked_at"] == "1970-01-01T00:00:00Z"
    assert not hasattr(baseline, "envelope") and "envelope" not in baseline.__all__
    assert not hasattr(baseline, "utc_stamp") and "utc_stamp" not in baseline.__all__


@pytest.mark.parametrize("value, usable", [
    ("2026-10-19T12:00:00Z", True), ("2026-10-19T12:00:00z", True), ("2026-10-19t12:00:00Z", True),
    ("\uff12\uff10\uff12\uff16-10-19T12:00:00Z", True), ("2026-10-19T12:00:00.5Z", False),
    ("2026-10-19T12:00:00+00:00", False), (" 2026-10-19T12:00:00Z", False), ("", False), (7, False),
    ("2026-13-45T00:00:00Z", False),
])
def test_an_events_row_counts_exactly_when_its_time_is_a_strict_stamp(tmp_path, value, usable):
    import json
    import subprocess

    from aegis_core import events

    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True, capture_output=True)
    path = events.events_path(tmp_path, create=True)
    row = {"v": events.EVENTS_VERSION, "ts": value, "event": events.KINDS[0], "worktree": "w", "result": "r",
           "detail": {}}
    path.write_bytes((json.dumps(row) + "\n").encode("utf-8"))
    assert len(events.read(tmp_path).rows) == (1 if usable else 0)
    assert (parse_utc(value) is not None) is usable


def _proposal_render(value):
    from aegis_core.proposals.model import clean_text

    return clean_text(value, 400)


# Display parity and redaction share boundaries even when legacy output keeps a kind byte.
def test_display_escape_boundaries_mask_secrets_on_every_surface(prefix, surface):
    from aegis_core import diagnostic_messages
    from aegis_core.redaction import redact_command_secrets

    key = "AK" + "IA" + "IOSFODNN7EXAMPLE"
    render = {"sanitize": lambda value: redact_command_secrets(primitives.sanitize_display(value, max_len=None)),
              "receipt": diagnostic_messages.receipt_value,
              "guidance": diagnostic_messages.guidance_value,
              "proposal": _proposal_render}[surface]
    for _ in range(2):
        shown = render(prefix + key)
        assert key not in shown
        assert "REDACTED" in shown


def test_display_removed_controls_preserve_secret_boundaries(code):
    from aegis_core import diagnostic_messages
    from aegis_core.redaction import redact_command_secrets

    key = "AK" + "IA" + "IOSFODNN7EXAMPLE"
    value = "note" + chr(code) + key
    for shown in (redact_command_secrets(primitives.sanitize_display(value, max_len=None)),
                  diagnostic_messages.receipt_value(value), diagnostic_messages.guidance_value(value),
                  _proposal_render(value)):
        assert key not in shown
        assert "REDACTED" in shown


def test_display_boundary_mask_preserves_legacy_kind_bytes_and_plain_baseline():
    from aegis_core.redaction import redact_command_secrets

    key = "AK" + "IA" + "IOSFODNN7EXAMPLE"
    assert primitives.sanitize_display("\x1bP" + key, max_len=None) == "P[REDACTED_AWS]"
    assert primitives.sanitize_display("plain " + key, max_len=None) == "plain " + key
    assert key not in redact_command_secrets(primitives.sanitize_display("plain " + key, max_len=None))
    assert primitives.sanitize_display("missing\x1b]FORGED", max_len=None) == "missing]FORGED"


def test_display_boundary_detection_keeps_secrets_split_by_inner_controls_masked():
    key = "AK" + "IA" + "IOSFODNN7EXAMPLE"
    value = "\x1bP" + key[:8] + "\x1b[31m" + key[8:]
    assert primitives.sanitize_display(value, max_len=None) == "P[REDACTED_AWS]"
    assert _proposal_render(value) == "P[REDACTED_AWS]"


def test_display_boundaries_are_local_to_parallel_calls_and_retries():
    from concurrent.futures import ThreadPoolExecutor

    key = "AK" + "IA" + "IOSFODNN7EXAMPLE"
    values = ["\x1bP" + key, "missing\x1b]FORGED", "plain " + key] * 12
    expected = ["P[REDACTED_AWS]", "missing]FORGED", "plain " + key] * 12
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(lambda value: primitives.sanitize_display(value, max_len=None), values)) == expected
    assert [primitives.sanitize_display(value, max_len=None) for value in values] == expected


def test_display_ten_million_removed_controls_do_not_build_per_control_state(tail):
    import tracemalloc

    from aegis_core import diagnostic_messages

    key = "AK" + "IA" + "IOSFODNN7EXAMPLE"
    value = "\r" * 10_000_000 + (key if tail == "secret" else tail)
    tracemalloc.start()
    try:
        assert primitives.sanitize_display(value, max_len=None) == ("[REDACTED_AWS]" if tail == "secret" else tail)
        assert diagnostic_messages.receipt_value(value) == "[diagnostic omitted: too_large]"
        assert diagnostic_messages.guidance_value(value) == "diagnostic_omitted_too_large"
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 2_000_000


def test_display_boundary_detection_uses_shared_secret_families(value, payload):
    from aegis_core import diagnostic_messages
    from aegis_core.redaction import redact_command_secrets

    for shown in (redact_command_secrets(primitives.sanitize_display("note\x1bP" + value, max_len=None)),
                  diagnostic_messages.receipt_value("note\x1bP" + value),
                  diagnostic_messages.guidance_value("note\x1bP" + value)):
        assert payload not in shown
        assert "REDACTED" in shown
    proposal = _proposal_render("note\x1bP" + value)
    assert payload not in proposal
    if "://" in value:
        # ROUND-8c preserves URL context before structural userinfo removal.
        assert proposal == "notephttps://example.test"
    else:
        assert "REDACTED" in proposal


def test_display_preserves_url_context_and_masks_overlapping_secret_rules():
    value = "https://user:" + "test-value-123456" + "@example.test"
    assert primitives.sanitize_display("note\x1bP" + value, max_len=None) == (
        "notePhttps://user:[REDACTED]@example.test")
    key = "AK" + "IA" + "IOSFODNN7EXAMPLE"
    shown = primitives.sanitize_display("note\x1bPtoken=" + key, max_len=None)
    assert shown.startswith("notePtoken=")
    assert key not in shown and "REDACTED" in shown


def test_display_provenance_masks_low_entropy_keys_after_every_header(prefix, surface):
    from aegis_core import diagnostic_messages
    from aegis_core.redaction import redact_command_secrets

    key = "AK" + "IA" + "A" * 16
    render = {"sanitize": lambda value: redact_command_secrets(primitives.sanitize_display(value, max_len=None)),
              "receipt": diagnostic_messages.receipt_value,
              "guidance": diagnostic_messages.guidance_value,
              "proposal": _proposal_render}[surface]
    for _ in range(2):
        shown = render(prefix + key)
        assert "A" * 16 not in shown
        assert "REDACTED" in shown


def test_display_provenance_masks_overlaps_inside_an_ordinary_match(family, surface):
    from aegis_core import diagnostic_messages
    from aegis_core.redaction import redact_command_secrets

    if family == "aws":
        first, second = "AK" + "IA" + "B" * 12, "AK" + "IA" + "A" * 16
        payloads = ("B" * 12, "A" * 16)
    else:
        first, second = "gh" + "p_" + "a" * 20, "gh" + "p_" + "a" * 36
        payloads = ("a" * 20, "a" * 36)
    render = {"sanitize": lambda value: redact_command_secrets(primitives.sanitize_display(value, max_len=None)),
              "receipt": diagnostic_messages.receipt_value,
              "guidance": diagnostic_messages.guidance_value,
              "proposal": _proposal_render}[surface]
    for _ in range(2):
        shown = render(first + "\r" + second)
        assert all(payload not in shown for payload in payloads)
        assert "REDACTED" in shown


def test_display_provenance_covers_every_string_form_and_header(introducer, header, surface):
    from aegis_core import diagnostic_messages
    from aegis_core.redaction import redact_command_secrets

    key = "AK" + "IA" + "A" * 16
    render = {"sanitize": lambda value: redact_command_secrets(primitives.sanitize_display(value, max_len=None)),
              "receipt": diagnostic_messages.receipt_value,
              "guidance": diagnostic_messages.guidance_value,
              "proposal": _proposal_render}[surface]
    shown = render(introducer + header + key)
    assert "A" * 16 not in shown
    assert "REDACTED" in shown


def test_display_provenance_overlaps_and_headers_are_independent_in_threads(surface):
    from concurrent.futures import ThreadPoolExecutor

    from aegis_core import diagnostic_messages
    from aegis_core.redaction import redact_command_secrets

    key = "AK" + "IA" + "A" * 16
    values = ["\x1b(0" + key, "\x1bP1" + key, "\x9d1" + key,
              "AK" + "IA" + "B" * 12 + "\r" + key,
              "gh" + "p_" + "a" * 20 + "\r" + "gh" + "p_" + "a" * 36] * 3
    render = {"sanitize": lambda value: redact_command_secrets(primitives.sanitize_display(value, max_len=None)),
              "receipt": diagnostic_messages.receipt_value,
              "guidance": diagnostic_messages.guidance_value,
              "proposal": _proposal_render}[surface]
    with ThreadPoolExecutor(max_workers=3) as pool:
        shown = list(pool.map(render, values))
    assert all("REDACTED" in value for value in shown)
    assert all(payload not in value for value in shown for payload in ("A" * 16, "B" * 12, "a" * 20))
    assert render("missing\x1b]FORGED") == render("missing]FORGED")


def test_display_source_view_masks_credentials_partly_consumed_by_csi(prefix, family, surface):
    from aegis_core import diagnostic_messages
    from aegis_core.redaction import redact_command_secrets

    key, payload = (("AK" + "IA" + "A" * 16, "A" * 16) if family == "aws" else
                    ("gh" + "p_" + "a" * 36, "a" * 36))
    render = {"sanitize": lambda value: redact_command_secrets(primitives.sanitize_display(value, max_len=None)),
              "receipt": diagnostic_messages.receipt_value,
              "guidance": diagnostic_messages.guidance_value,
              "proposal": _proposal_render}[surface]
    shown = render(prefix + key)
    assert payload not in shown
    assert "REDACTED" in shown
    assert shown == render("[REDACTED_AWS]" if family == "aws" else "[REDACTED_VCS_TOKEN]")


def test_display_source_view_keeps_header_state_across_ignored_controls(prefix, surface, control):
    from aegis_core import diagnostic_messages
    from aegis_core.redaction import redact_command_secrets

    key = "AK" + "IA" + "A" * 16
    render = {"sanitize": lambda value: redact_command_secrets(primitives.sanitize_display(value, max_len=None)),
              "receipt": diagnostic_messages.receipt_value,
              "guidance": diagnostic_messages.guidance_value,
              "proposal": _proposal_render}[surface]
    shown = render(prefix.replace("\x00", control) + key)
    assert "A" * 16 not in shown
    assert "REDACTED" in shown


def test_display_source_view_bounds_repeated_unterminated_pem_work():
    import subprocess

    script = (
        "from aegis_core.primitives import sanitize_display\n"
        "for control in ('\\r', '\\n'):\n"
        "    value = ('-----BEGIN ' + 'PRIVATE KEY-----x' + control) * 32768\n"
        "    assert sanitize_display(value, max_len=None) == '[REDACTED_PEM]'\n"
        "    assert sanitize_display(value) == '[REDACTED_PEM]'\n"
        "print('bounded')\n"
    )
    result = subprocess.run([sys.executable, "-c", script], cwd=primitives.aegis_import_root(),
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "bounded\n"


def test_display_source_view_accepts_control_only_nonsecret_text(value, expected):
    assert primitives.sanitize_display(value, max_len=None) == expected


def test_display_source_view_masks_only_surviving_characters_and_preserves_context():
    key = "AK" + "IA" + "A" * 16
    assert primitives.sanitize_display("before\x1b]" + key + "\x07after", max_len=None) == "beforeafter"
    assert primitives.sanitize_display("before\x1b[1" + key + " after", max_len=None) == "before[REDACTED_AWS] after"
    head, tail = "-----BEGIN " + "PRIVATE KEY-----", "-----END " + "PRIVATE KEY-----"
    value = head + "outer\r" + head + "inner" + tail + "\r" + key
    assert primitives.sanitize_display(value, max_len=None) == "[REDACTED_PEM][REDACTED_AWS]"


def test_display_deleted_view_masks_consumed_prefix_with_internal_control(prefix, inner, family, surface):
    from aegis_core import diagnostic_messages
    from aegis_core.redaction import redact_command_secrets

    key = "AK" + "IA" + "A" * 16 if family == "aws" else "gh" + "p_" + "a" * 36
    render = {"sanitize": lambda value: redact_command_secrets(primitives.sanitize_display(value, max_len=None)),
              "receipt": diagnostic_messages.receipt_value,
              "guidance": diagnostic_messages.guidance_value,
              "proposal": _proposal_render}[surface]
    shown = render(prefix + key[:4] + inner + key[4:])
    assert shown == render("[REDACTED_AWS]" if family == "aws" else "[REDACTED_VCS_TOKEN]")


def test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers(prefix, surface):
    from aegis_core import diagnostic_messages
    from aegis_core.redaction import redact_command_secrets

    key = "AK" + "IA" + "A" * 16
    render = {"sanitize": lambda value: redact_command_secrets(primitives.sanitize_display(value, max_len=None)),
              "receipt": diagnostic_messages.receipt_value,
              "guidance": diagnostic_messages.guidance_value,
              "proposal": _proposal_render}[surface]
    shown = render(prefix + key)
    assert "A" * 16 not in shown
    assert "REDACTED" in shown


def test_display_deleted_view_preserves_bel_termination_and_nonsecret_parity(introducer):
    key = "AK" + "IA" + "A" * 16
    assert primitives.sanitize_display("before" + introducer + key + "\x07after", max_len=None) == "beforeafter"
    assert primitives.sanitize_display("before" + introducer + "1\x072safe", max_len=None) == "before2safe"


def test_display_renderer_provenance_keeps_control_interrupted_headers(control, header, surface):
    from aegis_core import diagnostic_messages
    from aegis_core.redaction import redact_command_secrets

    key = "AK" + "IA" + "A" * 16
    render = {"sanitize": lambda value: redact_command_secrets(primitives.sanitize_display(value, max_len=None)),
              "receipt": diagnostic_messages.receipt_value,
              "guidance": diagnostic_messages.guidance_value,
              "proposal": _proposal_render}[surface]
    shown = render(header + control + ("B" if header.endswith("(") else "m") + key)
    assert "A" * 16 not in shown
    assert "REDACTED" in shown


def test_display_renderer_provenance_recovers_consumed_credential_label(surface):
    from aegis_core import diagnostic_messages
    from aegis_core.redaction import redact_command_secrets

    render = {"sanitize": lambda value: redact_command_secrets(primitives.sanitize_display(value, max_len=None)),
              "receipt": diagnostic_messages.receipt_value,
              "guidance": diagnostic_messages.guidance_value,
              "proposal": _proposal_render}[surface]
    shown = render("\x1bcredential=ab\rcdefgh")
    assert "abcdefgh" not in shown
    assert "REDACTED" in shown


def test_display_pem_extents_cover_differently_labelled_nested_body(surface, label):
    from aegis_core import diagnostic_messages
    from aegis_core.redaction import redact_command_secrets

    def head(value):
        return "-----BEGIN " + value + " PRIVATE KEY-----"

    value = head("RSA") + "\r" + head(label) + "-----END RSA PRIVATE KEY-----privatepayload"
    render = {"sanitize": lambda value: redact_command_secrets(primitives.sanitize_display(value, max_len=None)),
              "receipt": diagnostic_messages.receipt_value,
              "guidance": diagnostic_messages.guidance_value,
              "proposal": _proposal_render}[surface]
    shown = render(value)
    assert "privatepayload" not in shown
    assert "REDACTED" in shown


def test_display_source_segments_seal_suppressed_strings(introducer, terminator, hidden, tail, surface):
    from aegis_core import diagnostic_messages
    from aegis_core.redaction import redact_command_secrets

    render = {"sanitize": lambda value: redact_command_secrets(primitives.sanitize_display(value, max_len=None)),
              "receipt": diagnostic_messages.receipt_value,
              "guidance": diagnostic_messages.guidance_value,
              "proposal": _proposal_render}[surface]
    expected = render("before" + tail)
    if surface == "proposal" and hidden != "Bearer":
        # Measured proposal baseline redacts raw text before interpreting strings.
        expected = "before" + introducer[1:] + "0;" + ("token=[REDACTED]" if hidden == "token=" else "[REDACTED_PEM]")
    assert render("before" + introducer + "0;" + hidden + terminator + tail) == expected


def test_display_source_segments_do_not_invent_credential_whitespace(control, head, tail, surface):
    from aegis_core import diagnostic_messages
    from aegis_core.redaction import redact_command_secrets

    render = {"sanitize": lambda value: redact_command_secrets(primitives.sanitize_display(value, max_len=None)),
              "receipt": diagnostic_messages.receipt_value,
              "guidance": diagnostic_messages.guidance_value,
              "proposal": _proposal_render}[surface]
    expected = render(head + tail)
    if surface == "proposal" and control in ("\r", "\x85"):
        expected = "Bearer [REDACTED]" if head == "Bearer" else "password is [REDACTED]"
    assert render(head + control + tail) == expected


def test_display_source_segments_do_not_join_visible_context_through_hidden_payload(introducer, terminator, surface):
    from aegis_core import diagnostic_messages
    from aegis_core.redaction import redact_command_secrets

    render = {"sanitize": lambda value: redact_command_secrets(primitives.sanitize_display(value, max_len=None)),
              "receipt": diagnostic_messages.receipt_value,
              "guidance": diagnostic_messages.guidance_value,
              "proposal": _proposal_render}[surface]
    expected = "token=[REDACTED]" if surface == "proposal" else render("token=abc")
    assert render("token=" + introducer + "filler" + terminator + "abc") == expected


def test_display_source_segments_still_mask_visible_secrets_on_both_sides(introducer, terminator, surface):
    from aegis_core import diagnostic_messages
    from aegis_core.redaction import redact_command_secrets

    key = "AK" + "IA" + "A" * 16
    render = {"sanitize": lambda value: redact_command_secrets(primitives.sanitize_display(value, max_len=None)),
              "receipt": diagnostic_messages.receipt_value,
              "guidance": diagnostic_messages.guidance_value,
              "proposal": _proposal_render}[surface]
    shown = render(key + introducer + "0;ordinary" + terminator + key)
    assert "A" * 16 not in shown
    assert "REDACTED" in shown


def test_display_source_segments_keep_prefixed_secret_context_detectable(value, surface):
    from aegis_core import diagnostic_messages
    from aegis_core.redaction import redact_command_secrets

    render = {"sanitize": lambda value: redact_command_secrets(primitives.sanitize_display(value, max_len=None)),
              "receipt": diagnostic_messages.receipt_value,
              "guidance": diagnostic_messages.guidance_value,
              "proposal": _proposal_render}[surface]
    shown = render("note\x1bP" + value)
    assert "test-value-123456" not in shown
    if surface == "proposal" and "://" in value:
        assert shown == "notep" + value.split("://", 1)[0] + "://example.test"
    else:
        assert "REDACTED" in shown


def test_display_rendered_segments_seal_hidden_token_prefix(introducer, terminator, surface):
    from aegis_core import diagnostic_messages
    from aegis_core.redaction import redact_command_secrets

    render = {"sanitize": lambda value: redact_command_secrets(primitives.sanitize_display(value, max_len=None)),
              "receipt": diagnostic_messages.receipt_value,
              "guidance": diagnostic_messages.guidance_value,
              "proposal": _proposal_render}[surface]
    value = "before" + introducer + "0;gh" + "p_" + terminator + "a" * 20
    assert render(value) == render("before" + "a" * 20)


def test_display_rendered_segments_preserve_visible_space_inside_nonsecret(control, surface):
    from aegis_core import diagnostic_messages
    from aegis_core.redaction import redact_command_secrets

    render = {"sanitize": lambda value: redact_command_secrets(primitives.sanitize_display(value, max_len=None)),
              "receipt": diagnostic_messages.receipt_value,
              "guidance": diagnostic_messages.guidance_value,
              "proposal": _proposal_render}[surface]
    assert render("AK" + "IA" + control + "A" * 16) == render("AK" + "IA " + "A" * 16)


def test_display_rendered_segments_still_join_fully_removed_controls(control, surface):
    from aegis_core import diagnostic_messages
    from aegis_core.redaction import redact_command_secrets

    render = {"sanitize": lambda value: redact_command_secrets(primitives.sanitize_display(value, max_len=None)),
              "receipt": diagnostic_messages.receipt_value,
              "guidance": diagnostic_messages.guidance_value,
              "proposal": _proposal_render}[surface]
    shown = render("AK" + "IA" + control + "A" * 16)
    assert "A" * 16 not in shown
    assert "REDACTED" in shown


def test_display_rendered_segments_keep_visible_credential_whitespace(prefix, control, surface):
    from aegis_core import diagnostic_messages
    from aegis_core.redaction import redact_command_secrets

    render = {"sanitize": lambda value: redact_command_secrets(primitives.sanitize_display(value, max_len=None)),
              "receipt": diagnostic_messages.receipt_value,
              "guidance": diagnostic_messages.guidance_value,
              "proposal": _proposal_render}[surface]
    shown = render(prefix + "Bearer" + control + "a" * 20)
    assert "a" * 20 not in shown
    assert "REDACTED" in shown


def test_display_reassembled_tokens_use_markers_before_caller_redaction(family, removed, prefix):
    from aegis_core.redaction import redact_command_secrets

    key = "AK" + "IA" + "A" * 16 if family == "aws" else "gh" + "p_" + "a" * 36
    shown = primitives.sanitize_display(prefix + key[:2] + removed + key[2:], max_len=None)
    marker = "[REDACTED_AWS]" if family == "aws" else "[REDACTED_VCS_TOKEN]"
    assert shown == marker
    assert redact_command_secrets(shown) == marker
    assert _proposal_render(prefix + key[:2] + removed + key[2:]) == marker


def test_display_unions_canonical_and_source_only_masks(family):
    from aegis_core.redaction import redact_command_secrets

    key = "AK" + "IA" + "A" * 16 if family == "aws" else "gh" + "p_" + "a" * 36
    marker = "[REDACTED_AWS]" if family == "aws" else "[REDACTED_VCS_TOKEN]"
    value = "normal " + key + "; \x1bP1" + key
    shown = primitives.sanitize_display(value, max_len=None)
    assert shown == "normal " + marker + "; P1" + marker
    assert key not in redact_command_secrets(shown)
    assert _proposal_render(value) == "normal " + marker + "; P1" + marker


def test_display_does_not_orphan_value_after_guarding_secret_key_context(surface):
    from aegis_core import diagnostic_messages
    from aegis_core.redaction import redact_command_secrets

    key = "gh" + "p_" + "token" + "a" * 20
    render = {"sanitize": lambda value: redact_command_secrets(primitives.sanitize_display(value, max_len=None)),
              "receipt": diagnostic_messages.receipt_value,
              "guidance": diagnostic_messages.guidance_value,
              "proposal": _proposal_render}[surface]
    shown = render("note\x1bP" + key + "=unrelated-value-4321")
    assert "a" * 20 not in shown
    assert "unrelated-value-4321" not in shown
    assert "REDACTED" in shown


def test_display_restored_union_masks_before_boundary_changes_or_clipping(case, surface):
    from aegis_core import diagnostic_messages
    from aegis_core.redaction import redact_command_secrets

    key = "AK" + "IA" + "A" * 16
    token = "gh" + "p_pwd" + "a" * 17
    value = {"changed-boundary": "x" * 33 + "\rpwd=aaa!\r" + key,
             "ordered-coverage": "\x1b[31m" + token + "=bbbb",
             "finite-clip": "x" * 57 + " \r" + key + " tail"}[case]
    render = {"sanitize": lambda text: redact_command_secrets(primitives.sanitize_display(text)),
              "receipt": lambda text: diagnostic_messages.receipt_value(text, 400),
              "guidance": lambda text: diagnostic_messages.guidance_value(text, 400),
              "proposal": _proposal_render}[surface]
    shown = render(value)
    assert key not in shown and key[:19] not in shown
    assert token not in shown and "bbbb" not in shown
    assert "REDACTED" in shown


def test_display_source_guard_cannot_complete_a_new_credential_or_tear_a_mask(surface):
    from aegis_core import diagnostic_messages
    from aegis_core.redaction import redact_command_secrets

    value = "AK" + "IA" + "123456789PWD" + "\x1b=abcd"
    render = {"sanitize": lambda text: redact_command_secrets(primitives.sanitize_display(text, max_len=None)),
              "receipt": diagnostic_messages.receipt_value,
              "guidance": diagnostic_messages.guidance_value,
              "proposal": _proposal_render}[surface]
    shown = render(value)
    assert "abcd" not in shown and "omitted" not in shown
    expected = "AK" + "IA" + "123456789PWD"
    if surface == "proposal":
        # ROUND-8 addendum: the canonical-view entropy match covers this prefix.
        expected = "[REDACTED_HIENT]"
    assert shown == expected + (r"\x5bREDACTED\x5d" if surface == "guidance" else "[REDACTED]")


@pytest.mark.parametrize("count", [128, 1024, 8192])
def test_display_attribution_budget_masks_stress_before_interpretation_allocation(count, monkeypatch):
    observations = []
    original = primitives._display_attribution

    def observed(*args):
        spans, stats = original(*args)
        observations.append(dict(stats))
        return spans, stats

    def forbidden(*args):
        pytest.fail("an over-budget interpretation was allocated")

    monkeypatch.setattr("aegis_core.primitives._display_attribution", observed)
    monkeypatch.setattr("aegis_core.primitives._display_attribution_view", forbidden)
    value = "gh" + "p_" + "\x1b[a" * count + "!"
    assert primitives.sanitize_display(value, max_len=None) == "[REDACTED]"
    assert len(observations) == 1
    stats = observations[0]
    assert len(stats["windows"]) == 1
    assert stats["windows"][0]["coverage"] in {"possible", "exhausted"}
    assert stats["exhausted"] == (stats["windows"][0]["coverage"] == "exhausted")
    assert 0 < stats["steps"] <= stats["limit"] <= primitives._DISPLAY_ATTRIBUTION_CEILING
    assert stats["limit"] <= primitives._DISPLAY_ATTRIBUTION_RATE * len(value)


@pytest.mark.parametrize("value, expected", [
    ("plain", "plain"), ("\r\x00safe", "safe"),
    ("before\x1b]title", "before]title"), ("\x9b31mplain", "31mplain"),
    ("before\x1b]title\x07after", "beforeafter"), ("\t\n", "  "),
])
def test_display_attribution_gate_keeps_inputs_without_suppressed_finals_identical(value, expected, monkeypatch):
    def forbidden(*args):
        pytest.fail("attribution search ran without a suppressed printable final")

    monkeypatch.setattr("aegis_core.primitives._display_attribution", forbidden)
    assert primitives.sanitize_display(value, max_len=None) == expected


def test_display_attribution_preserves_ordinary_left_boundary(suffix):
    key = "AK" + "IA" + "A" * 16
    assert primitives.sanitize_display("x" + key + suffix, max_len=None) == "x" + key


def test_display_attribution_covers_shared_rule_families(value, payload, surface):
    from aegis_core import diagnostic_messages
    from aegis_core.redaction import redact_command_secrets

    render = {"sanitize": lambda text: redact_command_secrets(primitives.sanitize_display(text, max_len=None)),
              "receipt": diagnostic_messages.receipt_value,
              "guidance": diagnostic_messages.guidance_value,
              "proposal": _proposal_render}[surface]
    shown = render("\x1b[" + value[:4] + "\x1b[31m" + value[4:])
    assert payload not in shown
    if surface == "proposal" and "://" in value:
        assert shown == "ttps://example.test"
    else:
        assert "REDACTED" in shown


def test_display_attribution_budget_is_local_to_retries_and_parallel_calls():
    from concurrent.futures import ThreadPoolExecutor

    key = "AK" + "IA" + "A" * 16
    values = ["gh" + "p_" + "\x1b[a" * 128 + "!",
              "\x1b[" + key[:4] + "\x1b[31m" + key[4:], "safe"] * 8
    expected = ["[REDACTED]", "[REDACTED_AWS]", "safe"] * 8
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(lambda text: primitives.sanitize_display(text, max_len=None), values)) == expected
    assert [primitives.sanitize_display(text, max_len=None) for text in values] == expected


@pytest.mark.parametrize("surface", ["sanitize", "receipt", "guidance", "proposal"])
def test_display_attribution_exhaustion_masks_only_candidate_between_sealed_strings(surface, monkeypatch):
    from aegis_core import diagnostic_messages
    from aegis_core.redaction import redact_command_secrets

    monkeypatch.setattr("aegis_core.primitives._DISPLAY_ATTRIBUTION_CEILING", 0)
    key = "AK" + "IA" + "A" * 16
    candidate = "\x1b[" + key[:4] + "\x1b[31m" + key[4:]
    render = {"sanitize": lambda text: redact_command_secrets(primitives.sanitize_display(text, max_len=None)),
              "receipt": diagnostic_messages.receipt_value,
              "guidance": diagnostic_messages.guidance_value,
              "proposal": _proposal_render}[surface]
    value = "before\x1b]title\x07" + candidate + "\x1b]title\x07after"
    assert render(value) == render("before[REDACTED]after")


def test_display_attribution_long_benign_colour_runs_keep_parity(count):
    part = "x" * 5001
    value = (part + "\x1b[31m") * count + part
    assert primitives.sanitize_display(value, max_len=None) == part * (count + 1)


def test_display_attribution_adjacent_colours_keep_long_context():
    prefix, suffix = "left" * 1500, "right" * 1500
    value = prefix + "\x1b[31mone\x1b[0m \x1b[32mtwo\x1b[0m" + suffix
    assert primitives.sanitize_display(value, max_len=None) == prefix + "one two" + suffix


def test_display_attribution_exhaustion_masks_only_two_separate_windows(monkeypatch):
    observations = []
    original = primitives._display_attribution

    def observed(*args):
        spans, stats = original(*args)
        observations.extend(stats["windows"])
        return spans, stats

    monkeypatch.setattr("aegis_core.primitives._display_attribution", observed)
    monkeypatch.setattr("aegis_core.primitives._DISPLAY_ATTRIBUTION_CEILING", 0)
    part = "z" * (2 * primitives._display_attribution_tables()[0] + 77)
    value = part + "\x1b[31m" + part + "\x1b[31m" + part
    shown = primitives.sanitize_display(value, max_len=None)
    assert len(observations) == 2
    pieces, cursor = [], 0
    for stats in observations:
        assert stats["exhausted"] and stats["steps"] == stats["limit"] == 0
        pieces.extend((value[cursor:stats["start"]], "[REDACTED]"))
        cursor = stats["end"]
    pieces.append(value[cursor:])
    assert shown == "".join(pieces)
    assert shown.startswith("z" * 77) and shown.endswith("z" * 77)


def test_display_attribution_clipped_window_does_not_create_a_left_boundary():
    key = "AK" + "IA" + "A" * 16
    gap = "x" * (primitives._display_attribution_tables()[0] - len(key))
    plain = "x" * 5000 + key + gap
    assert primitives.sanitize_display(plain + "\x1b[31m", max_len=None) == plain


def test_display_attribution_exhausted_window_does_not_poison_later_window():
    key = "AK" + "IA" + "A" * 16
    first = "gh" + "p_" + "\x1b[a" * 128 + "!"
    second = "\x1b[" + key[:4] + "\x1b[31m" + key[4:]
    assert primitives.sanitize_display(first + "\x1b]title\x07" + second, max_len=None) == (
        "[REDACTED][REDACTED_AWS]")


def test_display_attribution_hidden_only_credential_does_not_mask_visible_context():
    key = "AK" + "IA" + "A" * 16
    value = "left" + "".join("\x1b[" + char for char in key)
    assert primitives.sanitize_display(value, max_len=None) == "left"


def test_display_attribution_widths_and_unknown_grammars_fail_conservatively():
    import re
    from aegis_core.display_attribution import compile_possible, max_match_width, may_match_visible

    assert max_match_width([re.compile(r"a{7}(?:bc|d)")], unbounded_cap=64) == 9
    assert max_match_width([re.compile(r"a*")], unbounded_cap=64) == 64
    assert max_match_width([re.compile(r"a{4096}")], unbounded_cap=64) == 4096
    assert compile_possible([re.compile(r"a{1000000}")]) is None
    assert compile_possible([re.compile(r"(ab)\1")]) is None
    runs = [(0, 4, 0, True, None, 0)]
    assert may_match_visible(None, "safe", runs, lambda amount: True)
    assert may_match_visible(compile_possible([re.compile("abc")]), "safe", runs, lambda amount: False)


def test_display_attribution_detection_windows_span_removed_control_gaps(count, control, surface):
    from aegis_core import diagnostic_messages
    from aegis_core.redaction import redact_command_secrets

    key = "AK" + "IA" + "A" * 16
    value = "\x1b[" + key[:4] + "\x1b[31m" + control * count + key[4:]
    render = {"sanitize": lambda text: redact_command_secrets(primitives.sanitize_display(text, max_len=None)),
              "receipt": diagnostic_messages.receipt_value,
              "guidance": diagnostic_messages.guidance_value,
              "proposal": _proposal_render}[surface]
    if surface == "proposal":
        from aegis_core.proposals.model import ProposalError

        with pytest.raises(ProposalError, match="^proposal refused: too_large$") as caught:
            render(value)
        assert caught.value.code == "too_large"
        return
    shown = render(value)
    if count == 5000:
        assert shown == render("[REDACTED_AWS]")
    elif surface == "sanitize":
        assert shown == "[REDACTED]"
    else:
        # These bounded surfaces refuse before invoking canonicalization.
        assert shown == {"receipt": "[diagnostic omitted: too_large]",
                         "guidance": "diagnostic_omitted_too_large"}[surface]
    assert "A" * 16 not in shown


def test_display_attribution_detection_windows_keep_visible_whitespace():
    key = "AK" + "IA" + "A" * 16
    value = "\x1b[" + key[:4] + "\x1b[31m" + "\t" * 5000 + key[4:]
    assert primitives.sanitize_display(value, max_len=None) == key[1:4] + " " * 5000 + key[4:]


def test_display_attribution_detection_windows_retry_after_large_gap_in_parallel():
    from concurrent.futures import ThreadPoolExecutor

    key = "AK" + "IA" + "A" * 16
    values = ["\x1b[" + key[:4] + "\x1b[31m" + "\x00" * count + key[4:]
              for count in (50000, 5000, 0)] * 4
    expected = ["[REDACTED]", "[REDACTED_AWS]", "[REDACTED_AWS]"] * 4
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(lambda value: primitives.sanitize_display(value, max_len=None), values)) == expected
    assert [primitives.sanitize_display(value, max_len=None) for value in values] == expected


@pytest.mark.parametrize("count", [5000, 50000])
@pytest.mark.parametrize("placement", ["prefix", "between", "payload"])
def test_display_attribution_detection_window_geometry_keeps_source_budget(count, placement, monkeypatch):
    observations = []
    original = primitives._display_attribution

    def observed(*args):
        spans, stats = original(*args)
        observations.extend(stats["windows"])
        return spans, stats

    monkeypatch.setattr("aegis_core.primitives._display_attribution", observed)
    key = "AK" + "IA" + "A" * 16
    gap = "\x00" * count
    value = {"prefix": "\x1b[" + key[:1] + gap + key[1:4] + "\x1b[31m" + key[4:],
             "between": "\x1b[" + key[:4] + gap + "\x1b[31m" + key[4:],
             "payload": "\x1b[" + key[:4] + "\x1b[31m" + gap + key[4:]}[placement]
    shown = primitives.sanitize_display(value, max_len=None)
    assert shown == ("[REDACTED_AWS]" if count == 5000 else "[REDACTED]")
    assert len(observations) == 1
    stats = observations[0]
    assert stats["detection_end"] - stats["detection_start"] == len(key) - 1
    assert stats["end"] == len(value)
    assert stats["source_length"] == stats["end"] - stats["start"]
    assert stats["source_length"] > count
    assert 0 < stats["steps"] <= stats["limit"] <= primitives._DISPLAY_ATTRIBUTION_CEILING
    assert stats["limit"] == min(primitives._DISPLAY_ATTRIBUTION_CEILING,
                                 primitives._DISPLAY_ATTRIBUTION_RATE * stats["source_length"])
    assert not stats["exhausted"]
    assert stats["coverage"] == ("possible" if count == 50000 else "complete")


def test_display_attribution_masks_overlapping_ordinary_credentials(surface, family):
    from aegis_core import diagnostic_messages
    from aegis_core.redaction import redact_command_secrets

    if family == "jwt":
        value = "eyJ" + "a" * 8 + ".aaaa_eyJ" + "b" * 8 + ".ccc\x1b[c." + "d" * 43
        signature, marker = "d" * 43, "[REDACTED_JWT]"
    else:
        prefix = "git" + "hub_pat_"
        value = prefix + "a" * 200 + "_" + prefix + "\x1b[b" + "b" * 99
        signature, marker = "b" * 43, "[REDACTED_VCS_TOKEN]"
    render = {"sanitize": lambda text: redact_command_secrets(primitives.sanitize_display(text, max_len=None)),
              "receipt": diagnostic_messages.receipt_value,
              "guidance": diagnostic_messages.guidance_value,
              "proposal": _proposal_render}[surface]
    shown = render(value)
    assert signature not in shown
    assert shown == render(marker)


def test_display_attribution_fallback_preserves_ordinary_boundary_and_flags(surface, plain):
    from aegis_core import diagnostic_messages
    from aegis_core.redaction import redact_command_secrets

    render = {"sanitize": lambda text: redact_command_secrets(primitives.sanitize_display(text, max_len=None)),
              "receipt": diagnostic_messages.receipt_value,
              "guidance": diagnostic_messages.guidance_value,
              "proposal": _proposal_render}[surface]
    assert render(plain + "\x1b[31m" * 128) == render(plain)


def test_display_attribution_fallback_keeps_carried_starts(surface):
    from aegis_core import diagnostic_messages
    from aegis_core.redaction import redact_command_secrets

    key = "AK" + "IA" + "A" * 16
    value = "x\x1b[" + key[:4] + "\x1b[31m" * 128 + key[4:]
    render = {"sanitize": lambda text: redact_command_secrets(primitives.sanitize_display(text, max_len=None)),
              "receipt": diagnostic_messages.receipt_value,
              "guidance": diagnostic_messages.guidance_value,
              "proposal": _proposal_render}[surface]
    shown = render(value)
    assert "A" * 16 not in shown and "REDACTED" in shown


def test_display_attribution_possible_match_is_not_budget_exhaustion(monkeypatch):
    observations = []
    original = primitives._display_attribution

    def observed(*args):
        spans, stats = original(*args)
        observations.extend(stats["windows"])
        return spans, stats

    monkeypatch.setattr("aegis_core.primitives._display_attribution", observed)
    value = "gh" + "p_" + "\x1b[a" * 128 + "!"
    assert primitives.sanitize_display(value, max_len=None) == "[REDACTED]"
    assert len(observations) == 1
    stats = observations[0]
    assert not stats["exhausted"]
    assert stats["coverage"] == "possible"
    assert stats["steps"] < stats["limit"]


def test_display_attribution_overlapping_scan_budget_refuses_and_retries(monkeypatch):
    observations, rejected = [], []
    original, original_charge = primitives._display_attribution, primitives._display_attribution_charge

    def observed(*args):
        spans, stats = original(*args)
        observations.extend(stats["windows"])
        return spans, stats

    def charged(stats, amount):
        allowed = original_charge(stats, amount)
        if not allowed:
            rejected.append(amount)
        return allowed

    monkeypatch.setattr("aegis_core.primitives._display_attribution", observed)
    monkeypatch.setattr("aegis_core.primitives._display_attribution_charge", charged)
    prefix = "git" + "hub_pat_"
    value = prefix + "a" * 200 + "_" + prefix + "\x1b[b" + "b" * 99
    original_ceiling = primitives._DISPLAY_ATTRIBUTION_CEILING
    monkeypatch.setattr("aegis_core.primitives._DISPLAY_ATTRIBUTION_CEILING", 70000)
    assert primitives.sanitize_display(value, max_len=None) == "[REDACTED]"
    stats = observations[0]
    assert stats["exhausted"] and stats["coverage"] == "exhausted"
    assert 0 < stats["steps"] <= stats["limit"] == 70000
    # The denied charge is a scan over detection text, after variant admission.
    assert rejected and max(rejected) <= len(value) + 1
    monkeypatch.setattr("aegis_core.primitives._DISPLAY_ATTRIBUTION_CEILING", original_ceiling)
    assert primitives.sanitize_display(value, max_len=None) == "[REDACTED_VCS_TOKEN]"
    assert observations[-1]["coverage"] == "complete" and not observations[-1]["exhausted"]


def test_display_attribution_overlaps_and_fallback_are_isolated_in_parallel():
    from concurrent.futures import ThreadPoolExecutor

    plain = "xAK" + "IA" + "A" * 16
    overlapping = "eyJ" + "a" * 8 + ".aaaa_eyJ" + "b" * 8 + ".ccc\x1b[c." + "d" * 43
    values = [overlapping, plain + "\x1b[31m" * 128, "gh" + "p_" + "\x1b[a" * 128 + "!"] * 4
    expected = ["[REDACTED_JWT]", plain, "[REDACTED]"] * 4
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(lambda value: primitives.sanitize_display(value, max_len=None), values)) == expected
    assert [primitives.sanitize_display(value, max_len=None) for value in values] == expected


# ── Proposal deleted-view redaction ──────────────────────────────────────────
# Invariant: a secret split by CR, NEL, or CSI is masked on the display deleted
# view before any whitespace join. Ordinary spaces still separate tokens.


@pytest.mark.parametrize("split,tail", [("cr", "cr"), ("nel", "nel"), ("vt", "vt"), ("ff", "ff"),
                                      ("mixed", "esc-intermediates"), ("esc-intermediates", "c1-intermediates")])
@pytest.mark.parametrize("placement", [None, -1, 0, 1], ids=["review", "before", "at", "after"])
def test_round8h_deleted_token_maps_to_first_source_character_and_recovers(split, tail, placement):
    from concurrent.futures import ThreadPoolExecutor
    from aegis_core.redaction import redact_insight_text
    from tests.unit.core.test_insights import _round8h_control_source

    prefix = "AK" + "IA" + "B" * 16 + " "
    source, _short, secret = _round8h_control_source(split, tail, placement, preceding=prefix)
    expected = "[REDACTED_AWS] Never repeat this: ..."

    def fail(_spans):
        raise RuntimeError("observer failed")

    def clean(_index):
        events = []
        shown = redact_insight_text(source, max_len=0, on_replacements=events.append)
        assert shown == expected and len(events) == 1
        assert events[0] == ((0, len(prefix) - 1, "[REDACTED_AWS]"),)
        assert all(secret[index:index + 4] not in shown for index in range(len(secret) - 3))
        assert redact_insight_text(shown, max_len=0) == shown
        return shown

    for _ in range(2):
        with pytest.raises(RuntimeError, match="^observer failed$"):
            redact_insight_text(source, max_len=0, on_replacements=fail)
        assert clean(0) == expected
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(clean, range(3))) == [expected] * 3


@pytest.mark.parametrize("separator", [" ", "\n", "\t", "\u2028", "\u2029", "\u00a0", "\u2003"],
                         ids=["space", "lf", "tab", "line", "paragraph", "nbsp", "em-space"])
@pytest.mark.parametrize("tail", ["cr", "nel", "vt", "ff", "esc-intermediates", "c1-intermediates"])
@pytest.mark.parametrize("last", ["A", ""], ids=["token", "empty-token"])
def test_round8h_genuine_deleted_view_whitespace_preserves_the_benign_head(tmp_path, separator, tail, last):
    from concurrent.futures import ThreadPoolExecutor
    from aegis_core.insights import add_insight, read_insight_rows
    from aegis_core.redaction import redact_insight_text
    from tests.unit.core.test_insights import _round8h_control_source

    benign = "abcdefghijklm" * 5
    # Use a genuine separator after the earlier split, before the final run.
    source, _short, _secret = _round8h_control_source("cr", tail)
    source = source.replace(benign + "\rA", benign + separator + last, 1)
    expected = "Never repeat this: " + benign + " ..."
    for _ in range(2):
        assert redact_insight_text(source, max_len=0) == expected
        assert redact_insight_text(expected, max_len=0) == expected
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(lambda _: redact_insight_text(source, max_len=0), range(3))) == [expected] * 3
    workspace = tmp_path / "ws"
    workspace.mkdir()
    for _ in range(2):
        row = add_insight(workspace, source, kind=source, paths=[], home=tmp_path / "home")
        assert row["text"] == expected and row["kind"] == expected
    assert all(row["text"] == expected and row["kind"] == expected
               for row in read_insight_rows(workspace, home=tmp_path / "home"))

def _proposal_key_shapes():
    """Both key families and both prefixes, generated rather than listed as samples."""
    return (
        ("AK" + "IA", "A" * 16, "[REDACTED_AWS]"),
        ("AS" + "IA", "A" * 16, "[REDACTED_AWS]"),
        ("gh" + "p_", "a" * 36, "[REDACTED_VCS_TOKEN]"),
        ("gh" + "o_", "a" * 36, "[REDACTED_VCS_TOKEN]"),
    )


def _proposal_control_matrix():
    """CR or NEL inside a key, with and without CSI, at both prefix cuts."""
    for prefix, body, marker in _proposal_key_shapes():
        key = prefix + body
        for cut in (2, len(prefix), len(prefix) + 8):
            for control in ("\r", "\x85"):
                for csi in ("", "\x1b[31m"):
                    yield key[:cut] + control + csi + key[cut:], body, marker, True
            yield key[:cut] + " " + key[cut:], body, marker, False


def _assert_proposal_view(shown, body, marker, masked):
    if masked:
        assert marker in shown
        assert body[:4] not in shown
    else:
        assert body[:4] in shown
        assert marker not in shown


def test_clean_text_masks_control_joined_keys_and_keeps_spaces():
    from aegis_core.proposals.model import clean_text

    cases = list(_proposal_control_matrix())
    assert len(cases) == 60
    for value, body, marker, masked in cases:
        shown = clean_text("note " + value + " tail", 300)
        _assert_proposal_view(shown, body, marker, masked)
        assert clean_text(shown, 300) == shown


def test_clean_text_control_join_is_stable_across_retries_and_threads():
    from concurrent.futures import ThreadPoolExecutor

    from aegis_core.proposals.model import ProposalError, clean_text

    cases = [row for row in _proposal_control_matrix() if row[3]]

    def once(row):
        value, _body, marker, _masked = row
        shown = clean_text(value, 300)
        again = clean_text(shown, 300)
        return shown == again and marker in shown and _body[:4] not in shown

    with ThreadPoolExecutor(max_workers=3) as pool:
        assert all(pool.map(once, cases * 2))
    with pytest.raises(ProposalError) as invalid:
        clean_text(None, 300)
    assert invalid.value.code == "invalid"
    assert "None" not in str(invalid.value)
    with pytest.raises(ProposalError) as oversized:
        clean_text("x" * 5000, 300)
    assert oversized.value.code == "too_large"
    assert "xxxx" not in str(oversized.value)


def test_clean_text_nonsecret_controls_keep_their_bytes():
    """Measure: controls that do not complete a secret stay on the pre-change bytes."""
    from aegis_core.proposals.model import clean_text
    from aegis_core.redaction import redact_insight_text

    expected = {
        "plain note": ("plain note", "plain note"),
        "hello\rworld": ("hello world", "hello world"),
        "hello\x85world": ("hello world", "hello world"),
        "hello\nworld": ("hello world", "hello world"),
        "hello\tworld": ("hello world", "hello world"),
        "a  b": ("a b", "a b"),
        "hello\x1b[31mworld": ("helloworld", "hello\x1b[31mworld"),
        "foo\rbar baz": ("foo bar baz", "foo bar baz"),
        "keep\x00join": ("keepjoin", "keep\x00join"),
        "password is hunter2": ("password is [REDACTED]", "password is [REDACTED]"),
    }
    for value, (cleaned, redacted) in expected.items():
        assert clean_text(value, 300) == cleaned
        assert redact_insight_text(value, max_len=0) == redacted


def test_proposal_benign_control_corpus_keeps_measured_baseline_bytes():
    import hashlib
    import json

    from aegis_core.proposals.model import clean_text
    from aegis_core.redaction import redact_insight_text

    controls = [chr(code) for code in (*range(32), *range(127, 160))]
    controls += [" ", "  ", "\x1b[31m", "\x1b]title\x07"]
    rows = [(clean_text(text, limit), redact_insight_text(text, max_len=limit))
            for control in controls
            for text in ("hello" + control + "world", "before " + control + "safe after",
                         "(" + control + "ordinary text)")
            for limit in (0, 64, 200)]
    assert len(rows) == 621
    measured = json.dumps(rows, ensure_ascii=True, separators=(",", ":")).encode()
    assert hashlib.sha256(measured).hexdigest() == "d1cb0ea660ed7c6c72ffa351dad9c9fd7f11904f976e96f4f150c5ff610f141c"


@pytest.mark.parametrize("value, limit, code", [
    (None, 20, "invalid"), ("safe", -1, "invalid"), ("safe", True, "invalid"),
    ("safe", "20", "invalid"), ("\r" * 21, 20, "too_large"),
])
def test_deleted_view_helper_refuses_before_parser_allocation(value, limit, code, monkeypatch):
    from aegis_core.redaction import RedactionRefusal

    def forbidden(*args):
        pytest.fail("a refused input reached display-view allocation")

    monkeypatch.setattr("aegis_core.primitives._display_views", forbidden)
    with pytest.raises(RedactionRefusal, match="^" + code + "$") as caught:
        primitives.redact_display_secrets(value, limit=limit)
    assert caught.value.code == code
    assert primitives.redact_display_secrets("safe", limit=4) == "safe"


def test_deleted_view_helper_callbacks_replay_retry_and_failure():
    from concurrent.futures import ThreadPoolExecutor

    from aegis_core.redaction import redact_insight_text

    values = [row[0] for row in _proposal_control_matrix() if row[3]]

    def once(value):
        state = [value]

        def observe(spans):
            parts, cursor = [], 0
            for start, end, replacement in spans:
                assert cursor <= start < end <= len(state[0])
                parts.extend((state[0][cursor:start], replacement))
                cursor = end
            parts.append(state[0][cursor:])
            state[0] = "".join(parts)

        shown = redact_insight_text(value, max_len=0, on_replacements=observe)
        assert shown == " ".join(state[0].split())
        assert primitives.redact_display_secrets(shown, limit=4096) == shown
        return shown

    def failing(spans):
        raise RuntimeError("observer failed")

    for _ in range(2):
        with pytest.raises(RuntimeError, match="^observer failed$"):
            primitives.redact_display_secrets(values[0], limit=4096, on_replacements=failing)
    expected = [once(value) for value in values]
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(once, values)) == expected


@pytest.mark.parametrize("prefix, body, marker", (*_proposal_key_shapes(),
                         ("https://user:", "a" * 16, "[REDACTED]")))
@pytest.mark.parametrize("control", ["\r", "\x85", "\r\x1b[31m", "\x85\x1b[31m"])
def test_insight_bound_drops_control_joined_key_fragments(prefix, body, marker, control):
    from aegis_core.redaction import MAX_LINE_LENGTH, redact_insight_text

    padding = "x " * ((MAX_LINE_LENGTH - len(prefix) - 9) // 2)
    value = padding + prefix + body[:8] + control + body[8:]
    value += ("@example.test" if "://" in prefix else "") + " tail" * 20
    assert len(value) > MAX_LINE_LENGTH
    for _ in range(2):
        shown = redact_insight_text(value, max_len=0)
        assert body[:4] not in shown
        assert redact_insight_text(shown, max_len=0) == shown


def test_insight_capture_persists_the_shared_deleted_view(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    from aegis_core.insights import add_insight, read_insight_rows

    workspace, home = tmp_path / "workspace", tmp_path / "capture-home"
    workspace.mkdir()
    (workspace / "app.py").write_text("pass\n", encoding="utf-8")
    cases = list(_proposal_control_matrix())

    def once(row):
        value, body, marker, masked = row
        insight = add_insight(workspace, "note " + value + " tail", paths=["app.py"],
                              kind="correctness", home=home)
        _assert_proposal_view(insight["text"], body, marker, masked)
        return insight["id"], insight["text"]

    expected = [once(row) for row in cases]
    with ThreadPoolExecutor(max_workers=3) as pool:
        concurrent = list(pool.map(once, cases))
    assert [text for _identity, text in concurrent] == [text for _identity, text in expected]
    stored = read_insight_rows(workspace, home=home)
    assert {identity for identity, _text in expected + concurrent} == {row["id"] for row in stored}
    by_id = {row["id"]: row["text"] for row in stored}
    for written in (expected, concurrent):
        for (identity, _text), shape in zip(written, cases):
            _assert_proposal_view(by_id[identity], *shape[1:])


def _guidance_bullets(text):
    body = text.split("## Guidance\n", 1)[1].split("## Evidence\n", 1)[0]
    return [line[2:] for line in body.splitlines() if line.startswith("- ")]


@pytest.mark.parametrize("supported", [False, True], ids=["unsupported", "supported"])
def test_proposal_writer_persists_the_deleted_view_mask(tmp_path, monkeypatch, supported):
    from aegis_core.insights import add_insight, write_proposal
    from aegis_core.proposals.model import ProposalError
    from aegis_core.storage import confined_descriptor_supported

    if supported and not confined_descriptor_supported():
        pytest.skip("requires descriptor-relative nofollow operations")
    if not supported:
        monkeypatch.setattr("aegis_core.proposals.store.descriptor_supported", lambda: False)

    workspace = tmp_path / "ws"
    workspace.mkdir()
    (workspace / "app.py").write_text("a = 1\n", encoding="utf-8")
    home = tmp_path / "home"
    member = add_insight(workspace, "counted member", paths=["app.py"], kind="correctness", home=home)
    cases = [row for row in _proposal_control_matrix() if row[3]]
    spaces = [row for row in _proposal_control_matrix() if not row[3]]
    for index, (value, body, marker, masked) in enumerate([*cases, *spaces]):
        bullet = "note " + value + " tail"
        proposal_id = f"trap-cv{index:02d}"
        path = write_proposal(workspace, proposal_id=proposal_id, insight_ids=[member["id"]],
                              summary_bullets=[bullet], kind="correctness", home=home)
        original = path.read_bytes()
        stored = _guidance_bullets(original.decode("utf-8"))[-1]
        _assert_proposal_view(stored, body, marker, masked)
        for _ in range(2):
            assert write_proposal(workspace, proposal_id=proposal_id, insight_ids=[member["id"]],
                                  summary_bullets=[bullet], kind="correctness", home=home) == path
            assert path.read_bytes() == original
    kind = "AS" + "IA" + "\x85" + "A" * 16
    path = write_proposal(workspace, proposal_id="trap-cv-kind", insight_ids=[member["id"]],
                          summary_bullets=["Keep the kind field on the same view."], kind=kind, home=home)
    head = path.read_text(encoding="utf-8").split("## Do", 1)[0]
    assert "[REDACTED_AWS]" in head
    assert "A" * 4 not in head
    with pytest.raises(ProposalError) as missing:
        write_proposal(workspace, proposal_id="trap-cv-missing", insight_ids=["ins-000000000000"],
                       summary_bullets=["note " + "AK" + "IA" + "\r" + "A" * 16 + " SENTINEL"],
                       kind="correctness", home=home)
    assert missing.value.code == "insight_counted"
    assert "SENTINEL" not in str(missing.value) and "A" * 4 not in str(missing.value)
    with pytest.raises(ProposalError) as refused:
        write_proposal(workspace, proposal_id="trap-cv-cr", insight_ids=[member["id"]],
                       summary_bullets=["ordinary bullet"], kind="AK" + "IA" + "\r" + "A" * 16, home=home)
    assert refused.value.code == "invalid"
    assert "A" * 4 not in str(refused.value)


# Round 4: detection precedes bounding and ordered substitutions keep context.

@pytest.mark.parametrize("aws", [False, True], ids=["keyed-value", "aws"])
def test_proposal_ordered_substitutions_keep_overlapping_context(tmp_path, aws):
    from concurrent.futures import ThreadPoolExecutor

    from aegis_core.insights import add_insight, read_insight_rows, write_proposal
    from aegis_core.proposals.model import clean_text
    from aegis_core.storage import confined_descriptor_supported

    label = "gh" + "p_token" + "a" * 20
    body = "B" * 16 if aws else "abcdefgh"
    value = label + ("=AK" + "IA" + "\x1b[31m" + body if aws
                     else "=abcd" + "\x1b[31m" + "efgh")
    workspace, home = tmp_path / "ws", tmp_path / "home"
    workspace.mkdir()
    (workspace / "app.py").write_text("pass\n", encoding="utf-8")
    shown = clean_text(value, 300)
    assert body[:4] not in shown and "[REDACTED" in shown
    assert clean_text(shown, 300) == shown

    def persist(_index):
        return add_insight(workspace, value, paths=["app.py"], kind="correctness", home=home)

    with ThreadPoolExecutor(max_workers=3) as pool:
        rows = list(pool.map(persist, range(3)))
    stored = {row["id"]: row["text"] for row in read_insight_rows(workspace, home=home)}
    assert all(body[:4] not in stored[row["id"]] for row in rows)
    if not confined_descriptor_supported():
        return  # Existing unsupported-probe writer test covers that path.
    proposal_ws = tmp_path / "proposal-ws"
    proposal_ws.mkdir()
    (proposal_ws / "app.py").write_text("pass\n", encoding="utf-8")
    member = add_insight(proposal_ws, "A counted proposal member.", paths=["app.py"], home=home)
    path = write_proposal(proposal_ws, proposal_id="trap-overlap", insight_ids=[member["id"]],
                          summary_bullets=[value], kind="correctness", home=home)
    original = path.read_bytes()
    assert body[:4] not in _guidance_bullets(original.decode("utf-8"))[-1]
    assert write_proposal(proposal_ws, proposal_id="trap-overlap", insight_ids=[member["id"]],
                          summary_bullets=[value], kind="correctness", home=home) == path
    assert path.read_bytes() == original


def _bound_crossing_secret(family, control, unfinished):
    shapes = {
        "jwt": ("eyJ" + "A" * 8 + ".abcdefgh", ".bbbb", "abcdefgh"),
        "url": ("https://user:abcdEFGHijkl", "@example.test", "abcdEFGHijkl"),
        "aws": ("AK" + "IA" + "B" * 8, "B" * 8, "B" * 16),
        "github": ("gh" + "p_" + "a" * 8, "a" * 28, "a" * 36),
    }
    left, right, body = shapes[family]
    repeats = 4097 if unfinished else 1
    return "note " + left + control * repeats + right + "z" * 4097, body


@pytest.mark.parametrize("family", ["jwt", "url", "aws", "github"])
@pytest.mark.parametrize("control", ["\r", "\x85", "\x1b[31m"], ids=["cr", "nel", "csi"])
@pytest.mark.parametrize("unfinished", [False, True], ids=["inside-raw", "unfinished"])
def test_bound_crossing_secret_matrix_persists_no_fragment(tmp_path, family, control, unfinished):
    from aegis_core.insights import add_insight, read_insight_rows
    from aegis_core.proposals.model import ProposalError, clean_text
    from aegis_core.redaction import MAX_LINE_LENGTH, redact_insight_text

    value, body = _bound_crossing_secret(family, control, unfinished)
    assert len(value) > MAX_LINE_LENGTH
    shown = redact_insight_text(value, max_len=0)
    assert body[:4] not in shown
    assert redact_insight_text(shown, max_len=0) == shown
    workspace, home = tmp_path / "ws", tmp_path / "home"
    workspace.mkdir()
    (workspace / "app.py").write_text("pass\n", encoding="utf-8")
    rows = [add_insight(workspace, value, paths=["app.py"], kind="correctness", home=home)
            for _ in range(2)]
    stored = {row["id"]: row["text"] for row in read_insight_rows(workspace, home=home)}
    assert all(body[:4] not in stored[row["id"]] for row in rows)
    with pytest.raises(ProposalError) as refused:
        clean_text(value, 300)
    assert refused.value.code == "too_large"
    assert body[:4] not in str(refused.value)
    short, _ = _bound_crossing_secret(family, control, False)
    short = short[:-4097]
    assert body[:4] not in clean_text(short, 300)
    from aegis_core.insights import write_proposal
    from aegis_core.storage import confined_descriptor_supported

    with pytest.raises(ProposalError) as oversized:
        write_proposal(workspace, proposal_id="trap-bound-long", insight_ids=[rows[0]["id"]],
                       summary_bullets=[value], kind="correctness", home=home)
    assert oversized.value.code == "too_large"
    assert body[:4] not in str(oversized.value)
    if confined_descriptor_supported():
        member = add_insight(workspace, "A counted matrix member.", paths=["app.py"], home=home)
        path = write_proposal(workspace, proposal_id="trap-bound-short", insight_ids=[member["id"]],
                              summary_bullets=[short], kind="correctness", home=home)
        original = path.read_bytes()
        assert body[:4] not in _guidance_bullets(original.decode("utf-8"))[-1]
        assert write_proposal(workspace, proposal_id="trap-bound-short", insight_ids=[member["id"]],
                              summary_bullets=[short], kind="correctness", home=home) == path
        assert path.read_bytes() == original


@pytest.mark.parametrize("control", ["\r", "\x85", "\x1b[31m"], ids=["cr", "nel", "csi"])
def test_ordered_keyed_value_keeps_context_with_trailing_control(tmp_path, control):
    from aegis_core.insights import add_insight, read_insight_rows
    from aegis_core.proposals.model import clean_text
    from aegis_core.redaction import redact_insight_text

    value = "gh" + "p_token" + "a" * 20 + "=abcdefgh" + control
    assert "abcd" not in redact_insight_text(value, max_len=0)
    assert "abcd" not in clean_text(value, 300)
    workspace = tmp_path / "ws"
    workspace.mkdir()
    (workspace / "app.py").write_text("pass\n", encoding="utf-8")
    row = add_insight(workspace, value, paths=["app.py"], home=tmp_path / "home")
    stored = {item["id"]: item["text"] for item in
              read_insight_rows(workspace, home=tmp_path / "home")}
    assert "abcd" not in stored[row["id"]]


@pytest.mark.parametrize("control", ["\r", "\x85"], ids=["cr", "nel"])
def test_review_unfinished_jwt_never_persists_payload(tmp_path, control):
    from aegis_core.insights import add_insight, read_insight_rows

    value = "eyJ" + "A" * 8 + ".abcdefgh" + control * 4097 + ".bbbb"
    workspace = tmp_path / "ws"
    workspace.mkdir()
    (workspace / "app.py").write_text("pass\n", encoding="utf-8")
    row = add_insight(workspace, value, paths=["app.py"], home=tmp_path / "home")
    stored = {item["id"]: item["text"] for item in
              read_insight_rows(workspace, home=tmp_path / "home")}
    assert "abcd" not in stored[row["id"]]


def test_bounded_deleted_view_callbacks_fail_retry_and_parallel():
    from concurrent.futures import ThreadPoolExecutor

    from aegis_core.redaction import RedactionRefusal

    value = "AK" + "IA" + "B" * 8 + "\r" + "B" * 8 + " safe " + "tail" * 100

    def failing(_spans):
        raise RuntimeError("observer failed")

    with pytest.raises(RuntimeError, match="^observer failed$"):
        primitives.redact_display_secrets(value, limit=4096, bound=True, on_replacements=failing)

    def once(_index):
        events = []
        shown = primitives.redact_display_secrets(value, limit=4096, bound=True,
                                                  on_replacements=events.extend)
        assert events and all(0 <= start < end <= len(value) for start, end, _payload in events)
        assert "BBBB" not in shown
        return shown

    expected = once(0)
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(once, range(6))) == [expected] * 6
    for invalid in (None, 1, "yes"):
        with pytest.raises(RedactionRefusal, match="^invalid$") as caught:
            primitives.redact_display_secrets(value, limit=4096, bound=invalid)
        assert caught.value.code == "invalid"
    assert once(0) == expected


@pytest.mark.parametrize("token", ["gh" + "p_" + "a" * 20, "AK" + "IA" + "B" * 16,
                                  "sk-" + "a" * 24, "npm_" + "a" * 24])
@pytest.mark.parametrize("control", ["\r", "\x85", " \x1b[31m"], ids=["cr", "nel", "csi"])
def test_round6_original_bearer_context_survives_embedded_tokens(tmp_path, token, control):
    from concurrent.futures import ThreadPoolExecutor

    from aegis_core.insights import add_insight, read_insight_rows, write_proposal
    from aegis_core.proposals.model import clean_text
    from aegis_core.redaction import redact_insight_text
    from aegis_core.storage import confined_descriptor_supported

    value = "Bearer" + control + token + ".bbbbbbbb"
    for clean in (lambda text: primitives.redact_display_secrets(text, limit=4096),
                  lambda text: redact_insight_text(text, max_len=0), lambda text: clean_text(text, 300)):
        shown = clean(value)
        assert "bbbb" not in shown and "[REDACTED" in shown
        assert clean(shown) == shown
    workspace, home = tmp_path / "ws", tmp_path / "home"
    workspace.mkdir()
    (workspace / "app.py").write_text("pass\n", encoding="utf-8")

    def persist(_index):
        return add_insight(workspace, value, paths=["app.py"], home=home)

    with ThreadPoolExecutor(max_workers=3) as pool:
        rows = list(pool.map(persist, range(6)))
    by_id = {row["id"]: row["text"] for row in read_insight_rows(workspace, home=home)}
    assert all("bbbb" not in by_id[row["id"]] for row in rows)
    if not confined_descriptor_supported():
        return  # The existing unsupported-probe writer test exercises refusal.
    proposal_ws = tmp_path / "proposal-ws"
    proposal_ws.mkdir()
    (proposal_ws / "app.py").write_text("pass\n", encoding="utf-8")
    member = add_insight(proposal_ws, "Counted ordinary member.", paths=["app.py"], home=home)
    arguments = dict(proposal_id="trap-bearer", insight_ids=[member["id"]],
                     summary_bullets=[value], kind="correctness", home=home)
    path = write_proposal(proposal_ws, **arguments)
    original = path.read_bytes()
    assert "bbbb" not in _guidance_bullets(original.decode("utf-8"))[-1]
    assert write_proposal(proposal_ws, **arguments) == path
    assert path.read_bytes() == original


@pytest.mark.parametrize("control", ["\r", "\x85", "\x1b[31m"], ids=["cr", "nel", "csi"])
def test_round6_insight_kind_is_redacted_before_both_writes(tmp_path, control):
    from concurrent.futures import ThreadPoolExecutor

    from aegis_core.insights import add_insight, read_insight_rows, record_decision

    workspace, home = tmp_path / "ws", tmp_path / "home"
    workspace.mkdir()
    (workspace / "app.py").write_text("pass\n", encoding="utf-8")
    kind = "AK" + "IA" + control + "B" * 16
    with pytest.raises(ValueError, match="^confirm needs at least one insight id$"):
        record_decision(workspace, decision="confirm", insight_ids=[], kind=kind, home=home)

    def persist(_index):
        row = add_insight(workspace, "Ordinary correction.", paths=["app.py"], kind=kind, home=home)
        decision = record_decision(workspace, decision="confirm", insight_ids=[row["id"]],
                                   kind=kind, home=home)
        assert row["kind"] == decision["kind"] == "[REDACTED_AWS]"
        return row["id"]

    persist(0)
    with ThreadPoolExecutor(max_workers=3) as pool:
        identities = set(pool.map(persist, range(6)))
    stored = read_insight_rows(workspace, home=home)
    assert identities <= {row["id"] for row in stored if row["event"] == "insight"}
    assert all(row["kind"] == "[REDACTED_AWS]" for row in stored)


@pytest.mark.parametrize("control", ["cr", "nel", "nul", "ignored-c1", "esc-parameters", "esc-intermediates",
                                     "c1-parameters", "c1-intermediates"])
@pytest.mark.parametrize("placement", [None, -1, 0, 1], ids=["review", "before", "at", "after"])
@pytest.mark.parametrize("case", ["security", "correctness-letters", "correctness-symbols"])
def test_round8g_raw_tail_cut_retains_prior_replacements_and_recovers(control, placement, case):
    from concurrent.futures import ThreadPoolExecutor
    from aegis_core.redaction import redact_insight_text
    from tests.unit.core.test_insights import _round8g_control_source

    prefix = "token=" + "x" * 10 + " "
    source, _short, secret = _round8g_control_source(control, placement, preceding=prefix, case=case)
    expected = "token=[REDACTED] " + ("Never repeat this:" if case == "security" else "First safe note.") + " ..."

    def fail(_spans):
        raise RuntimeError("observer failed")

    def clean(_index):
        events = []
        shown = redact_insight_text(source, max_len=0, on_replacements=events.append)
        assert shown == expected
        assert len(events) == 1
        assert all(end <= len(prefix) for _start, end, _payload in events[0])
        assert all(secret[index:index + 4] not in shown for index in range(len(secret) - 3))
        assert redact_insight_text(shown, max_len=0) == shown
        return shown

    for _ in range(2):
        with pytest.raises(RuntimeError, match="^observer failed$"):
            redact_insight_text(source, max_len=0, on_replacements=fail)
        assert clean(0) == expected
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(clean, range(3))) == [expected] * 3


@pytest.mark.parametrize("control", ["\r", "\x85"], ids=["cr", "nel"])
@pytest.mark.parametrize("word", ["note", "ordinary", "AKIAnote", "ghp_ordinary!"])
def test_round6_benign_control_text_keeps_historical_bounded_head(tmp_path, control, word):
    from concurrent.futures import ThreadPoolExecutor

    from aegis_core.insights import add_insight, read_insight_rows
    from aegis_core.redaction import redact_insight_text

    value = (word + control) * 1000
    # ROUND-8h: these raw words are one token in the deleted view. Withhold
    # that entire token when its joining control run meets the bound.
    expected = "..."

    def clean(_index):
        shown = redact_insight_text(value, max_len=0)
        assert shown == expected
        assert redact_insight_text(shown, max_len=0) == shown
        return shown

    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(clean, range(6))) == [expected] * 6
    workspace, home = tmp_path / "ws", tmp_path / "home"
    workspace.mkdir()
    (workspace / "app.py").write_text("pass\n", encoding="utf-8")
    for _ in range(2):
        row = add_insight(workspace, value, paths=["app.py"], home=home)
        assert row["text"] == expected[:300]
    assert all(row["text"] == expected[:300] for row in read_insight_rows(workspace, home=home))


@pytest.mark.parametrize("control", ["cr", "nel", "esc-intermediates", "c1-intermediates"])
@pytest.mark.parametrize("token", ["ordinary", "a" * 65, "a" * 513, "123" * 30, "!?" * 40, "ordinary "],
                         ids=["word", "long-letters", "longer-letters", "digits", "punctuation", "space-before-run"])
def test_round8g_control_tail_does_not_classify_the_raw_token(control, token):
    from concurrent.futures import ThreadPoolExecutor
    from aegis_core.redaction import redact_insight_text
    from tests.unit.core.test_insights import _round8g_control_source

    source, _short, _secret = _round8g_control_source(control, token=token)
    # ROUND-8h: retained whitespace ends the deleted-view token before the run.
    expected = "Never repeat this: " + (token if token.endswith(" ") else "") + "..."
    for _ in range(2):
        assert redact_insight_text(source, max_len=0) == expected
        assert redact_insight_text(expected, max_len=0) == expected
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(lambda _: redact_insight_text(source, max_len=0), range(3))) == [expected] * 3


@pytest.mark.parametrize("control", ["\r", "\x85", "\x1b[" + " " * 5000 + "m"], ids=["cr", "nel", "csi"])
@pytest.mark.parametrize("candidate", ["k7Qm9pL2xV4nR8wY", "person", "AKIABBBBBBBB"])
def test_round8f_tail_withholds_only_candidate_and_keeps_benign_head(control, candidate):
    from concurrent.futures import ThreadPoolExecutor
    from aegis_core.redaction import redact_insight_text

    removed = control if len(control) > 1 else control * 5000
    source = "First safe note. " + candidate + removed + "tail"

    def clean(_index):
        events = []
        shown = redact_insight_text(source, max_len=0, on_replacements=events.append)
        assert shown == "First safe note. ..."
        assert events == []  # Initial bounding does not report replacement spans.
        assert redact_insight_text(shown, max_len=0) == shown
        return shown

    expected = clean(0)
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(clean, range(6))) == [expected] * 6


@pytest.mark.parametrize("label", ["PRIVATE KEY", "RSA PRIVATE KEY", "OPENSSH PRIVATE KEY"])
@pytest.mark.parametrize("where", ["body", "end-line"])
def test_round8f_pem_bound_retains_benign_prefix_and_callback_failure_recovers(label, where):
    from concurrent.futures import ThreadPoolExecutor
    from aegis_core.redaction import redact_insight_text

    prefix = "token=secret12345 First safe note. "
    begin, end = "-----BEGIN " + label + "-----\n", "-----END " + label + "-----"
    body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC+/\n" * 200
    if where == "end-line":
        body = body[:4090 - len(prefix) - len(begin)]
    source = prefix + begin + body + end + " tail" * 100
    expected = "token=[REDACTED] First safe note."

    def fail(_spans):
        raise RuntimeError("observer failed")

    def clean(_index):
        events = []
        shown = redact_insight_text(source, max_len=0, on_replacements=events.append)
        assert shown == expected and len(events) == 1
        assert all(end <= len(prefix) for _start, end, _payload in events[0])
        assert redact_insight_text(shown, max_len=0) == shown
        return shown

    for _ in range(2):
        with pytest.raises(RuntimeError, match="^observer failed$"):
            redact_insight_text(source, max_len=0, on_replacements=fail)
        assert clean(0) == expected
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(clean, range(6))) == [expected] * 6


@pytest.mark.parametrize("candidate_scan", [False, 1, "bad", []])
def test_round8f_invalid_tail_metadata_refuses_before_parsing_then_retries(monkeypatch, candidate_scan):
    from aegis_core.redaction import RedactionRefusal

    original = primitives._display_views

    def forbidden(*args, **kwargs):
        pytest.fail("invalid tail metadata reached display parsing")

    monkeypatch.setattr("aegis_core.primitives._display_views", forbidden)
    for _ in range(2):
        with pytest.raises(RedactionRefusal, match="^invalid$") as caught:
            primitives.redact_display_secrets("safe", limit=4, bound=True, tail_candidates=candidate_scan)
        assert caught.value.code == "invalid"
    monkeypatch.setattr("aegis_core.primitives._display_views", original)
    assert primitives.redact_display_secrets("safe ", limit=5, bound=True, tail_candidates=lambda _text: ()) == "safe "


@pytest.mark.parametrize("label", ["PRIVATE KEY", "RSA PRIVATE KEY", "OPENSSH PRIVATE KEY"])
def test_round8f_completed_pem_before_later_cut_keeps_intervening_benign_text(label):
    from concurrent.futures import ThreadPoolExecutor
    from aegis_core.redaction import redact_insight_text

    first = "-----BEGIN " + "PRIVATE KEY-----\nABCD\n-----END " + "PRIVATE KEY-----"
    prefix = "First safe note. " + first + " Middle safe note. "
    source = prefix + "-----BEGIN " + label + "-----\n" + "ABCD+/\n" * 1000
    expected = "First safe note. [REDACTED_PEM] Middle safe note."

    def fail(_spans):
        raise RuntimeError("observer failed")

    def clean(_index):
        events = []
        shown = redact_insight_text(source, max_len=0, on_replacements=events.append)
        assert shown == expected and len(events) == 1
        assert events[0] == ((prefix.index("-----BEGIN"), prefix.index(" Middle"), "[REDACTED_PEM]"),)
        assert redact_insight_text(shown, max_len=0) == shown
        return shown

    for _ in range(2):
        with pytest.raises(RuntimeError, match="^observer failed$"):
            redact_insight_text(source, max_len=0, on_replacements=fail)
        assert clean(0) == expected
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(clean, range(6))) == [expected] * 6


def test_round6_original_union_callback_is_single_replayable_and_recovers():
    from concurrent.futures import ThreadPoolExecutor

    from aegis_core.redaction import redact_insight_text

    value = "Bearer\rgh" + "p_" + "a" * 20 + ".bbbbbbbb mail person@example.test"

    def fail(_spans):
        raise RuntimeError("observer failed")

    for _ in range(2):
        with pytest.raises(RuntimeError, match="^observer failed$"):
            redact_insight_text(value, max_len=0, on_replacements=fail)

    def clean(_index):
        events = []
        shown = redact_insight_text(value, max_len=0, on_replacements=events.append)
        assert len(events) == 1
        parts, cursor = [], 0
        for start, end, replacement in events[0]:
            assert cursor <= start < end <= len(value)
            parts.extend((value[cursor:start], replacement))
            cursor = end
        parts.append(value[cursor:])
        assert shown == " ".join("".join(parts).split())
        assert "bbbb" not in shown and "person@" not in shown
        return shown

    expected = clean(0)
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(clean, range(6))) == [expected] * 6


@pytest.mark.parametrize("spans", [None, [], ((0, 0, "mask"),), ((0, 5, "mask"),),
                                  ((False, 2, "mask"),), ((0, 2, None),), ((0, 2),)])
def test_round6_extra_spans_refuse_before_allocation_then_retry(monkeypatch, spans):
    from aegis_core.redaction import RedactionRefusal

    def forbidden(*args):
        pytest.fail("invalid spans reached display allocation")

    original = primitives._display_views
    monkeypatch.setattr("aegis_core.primitives._display_views", forbidden)
    for _ in range(2):
        with pytest.raises(RedactionRefusal, match="^invalid$") as caught:
            primitives.redact_display_secrets("safe", limit=4, extra_spans=spans)
        assert caught.value.code == "invalid"
    monkeypatch.setattr("aegis_core.primitives._display_views", original)
    assert primitives.redact_display_secrets("safe", limit=4, extra_spans=((0, 4, "[REDACTED]"),)) == "[REDACTED]"


@pytest.mark.parametrize("value, expected", [
    ("/home/person@example.test", "/home/~user"),
    ("/Users/person@example.test", "/Users/~user"),
    ("C:\\Users\\person@example.test", "C:\\Users\\~user"),
    ("https://user:secret123@example.test", "https://user:[REDACTED]@example.test"),
    ("person@example.test", "[REDACTED_EMAIL]"),
    ("/home/10.20.30.40", "/home/~user"),
])
def test_round6_privacy_context_keeps_historical_bytes(value, expected):
    from concurrent.futures import ThreadPoolExecutor

    from aegis_core.redaction import redact_insight_text

    def fail(_spans):
        raise RuntimeError("observer failed")

    def clean(_index):
        events = []
        shown = redact_insight_text(value, max_len=0, on_replacements=events.append)
        assert shown == expected and len(events) == 1
        assert redact_insight_text(shown, max_len=0) == shown
        return shown

    for _ in range(2):
        with pytest.raises(RuntimeError, match="^observer failed$"):
            redact_insight_text(value, max_len=0, on_replacements=fail)
        assert clean(0) == expected
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(clean, range(6))) == [expected] * 6


@pytest.mark.parametrize("control", ["\r", "\x85", "\x00", "\x1b[31m", "\x9b31m"],
                         ids=["cr", "nel", "nul", "esc", "c1"])
@pytest.mark.parametrize("position", [4095, 4096, 4097], ids=["before", "at", "after"])
def test_round8e_conservative_control_window_and_plain_head(control, position):
    from aegis_core.redaction import redact_insight_text

    benign = "First safe note. " + "ordinary " * 1200
    raw = benign[:4097]
    words = raw.split()
    if not raw[-1].isspace():
        words.pop()
    expected = " ".join(words)
    assert redact_insight_text(benign, max_len=0) == expected
    source = benign[:position] + control + benign[position + 1:]
    shown = redact_insight_text(source, max_len=0)
    assert shown.startswith(expected)
    if position == 4097:
        assert shown == expected
    else:
        assert shown[len(expected):].strip(" .") == ""
    assert redact_insight_text(shown, max_len=0) == shown


def _round8_credential_families():
    from tests.unit.cli.test_check_ci_push import REDACTION_FAMILY_PROBES

    return [row for row in REDACTION_FAMILY_PROBES if row[0] not in {"email", "home", "ip"}]


@pytest.mark.parametrize("control", ["\r", "\x85", "\x00", "\x7f", "\x86"], ids=["cr", "nel", "nul", "del", "c1"])
def test_round8e_entropy_bound_resolves_removed_runs(control):
    from aegis_core.redaction import redact_insight_text

    secret = "k7Qm9pL2xV4nR8wY3tB6cD1fH0aZ"
    value = "First safe note. " + secret[:16] + control * 4097 + secret[16:]
    shown = redact_insight_text(value, max_len=0)
    assert shown == "First safe note. ..."
    assert all(secret[index:index + 4] not in shown for index in range(len(secret) - 3))
    assert redact_insight_text(shown, max_len=0) == shown


@pytest.mark.parametrize("intro", ["\x1b[", "\x9b"], ids=["esc", "c1"])
@pytest.mark.parametrize("header", ["1;", " "], ids=["parameters", "intermediates"])
@pytest.mark.parametrize("count", [5000, 30000], ids=["resolved", "exhausted"])
@pytest.mark.parametrize("tail", ["m" + "B" * 8, ""], ids=["complete", "unfinished"])
def test_round8e_bound_inside_csi_never_keeps_credential_fragments(tmp_path, intro, header, count, tail):
    from concurrent.futures import ThreadPoolExecutor
    from aegis_core.insights import add_insight, read_insight_rows
    from aegis_core.redaction import redact_insight_text

    value = "First safe note. x\rAKIA" + "B" * 8 + intro + header * count + tail

    def clean(_index):
        shown = redact_insight_text(value, max_len=0)
        # ROUND-8h: the earlier CR joins x to the candidate in the deleted view.
        assert shown == "First safe note. ..."
        assert "BBBB" not in shown
        assert redact_insight_text(shown, max_len=0) == shown
        return shown

    expected = clean(0)
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(clean, range(6))) == [expected] * 6
    workspace, home = tmp_path / "ws", tmp_path / "home"
    workspace.mkdir()
    for _ in range(2):
        row = add_insight(workspace, value, paths=[], home=home)
        assert "BBBB" not in row["text"]
    assert all("BBBB" not in row["text"] for row in read_insight_rows(workspace, home=home))


@pytest.mark.parametrize("control", ["\r", "\x85", "\x00", "\x1b[" + " " * 30000 + "m"],
                         ids=["cr", "nel", "nul", "csi"])
@pytest.mark.parametrize("token", ["harmless", "k7Qm9pL2xV4nR8wY", "person@example"],
                         ids=["benign", "entropy", "privacy"])
def test_round8e_control_tail_is_withheld_before_matching_and_recovers(monkeypatch, control, token):
    from concurrent.futures import ThreadPoolExecutor
    from aegis_core import redaction

    removed = control if len(control) > 1 else control * 50000
    source = "token=secret12345 First second " + token + removed + "tail"
    original_control, original_spans = redaction.CONTROL_RE, redaction._text_spans
    original_views, sizes = primitives._display_views, []

    class BoundedControls:
        def search(self, text):
            sizes.append(len(text))
            assert len(text) <= redaction.MAX_LINE_LENGTH + 1
            return original_control.search(text)

    def bounded_views(text, *args, **kwargs):
        assert len(text) <= redaction.MAX_LINE_LENGTH + 1
        return original_views(text, *args, **kwargs)

    def bounded_spans(text):
        assert len(text) <= redaction.MAX_LINE_LENGTH + 1
        return original_spans(text)

    monkeypatch.setattr("aegis_core.redaction.CONTROL_RE", BoundedControls())
    monkeypatch.setattr("aegis_core.primitives._display_views", bounded_views)
    monkeypatch.setattr("aegis_core.redaction._text_spans", bounded_spans)

    def fail(_spans):
        raise RuntimeError("observer failed")

    for _ in range(2):  # The retained earlier secret still reports one replacement.
        with pytest.raises(RuntimeError, match="^observer failed$"):
            redaction.redact_insight_text(source, max_len=0, on_replacements=fail)

    def clean(_index):
        events = []
        shown = redaction.redact_insight_text(source, max_len=0, on_replacements=events.append)
        assert shown == "token=[REDACTED] First second ..." and len(events) == 1
        assert all(end <= source.index(" First") for _start, end, _payload in events[0])
        return shown

    expected = clean(0)
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(clean, range(6))) == [expected] * 6
    assert sizes and max(sizes) == redaction.MAX_LINE_LENGTH + 1
    monkeypatch.setattr("aegis_core.redaction.CONTROL_RE", original_control)
    monkeypatch.setattr("aegis_core.primitives._display_views", original_views)
    monkeypatch.setattr("aegis_core.redaction._text_spans", original_spans)
    safe = "token=secret12345 First second"
    for _ in range(2):
        with pytest.raises(RuntimeError, match="^observer failed$"):
            redaction.redact_insight_text(safe, max_len=0, on_replacements=fail)
    assert redaction.redact_insight_text(safe, max_len=0) == "token=[REDACTED] First second"


@pytest.mark.parametrize("family,value,secret,marker", _round8_credential_families())
@pytest.mark.parametrize("control", ["\r", "\x85", "\x1b[31m"], ids=["cr", "nel", "csi"])
@pytest.mark.parametrize("placement", ["before", "at", "after"])
def test_round8_carried_unfinished_candidate_matrix(tmp_path, family, value, secret, marker, control, placement):
    from concurrent.futures import ThreadPoolExecutor

    from aegis_core.insights import add_insight, read_insight_rows
    from aegis_core.redaction import redact_insight_text

    import re

    run = re.search(r"([A-Za-z0-9])\1{3,}$", secret)
    body = run.group() if run else secret
    split = value.index(secret) + (run.start() if run else 0) + min(8, max(4, len(body) // 2))
    head, tail = value[:split], value[split:]
    if placement == "before":
        source = "note x" + control + head + control * 4097 + tail
    else:
        position = 4096 if placement == "at" else 4098
        padding = ("note " * 1000)[:position - len(control) - 1]
        source = padding + "x" + control + head + control * 4097 + tail

    def clean(_index):
        shown = redact_insight_text(source, max_len=0)
        assert body[:4] not in shown
        assert redact_insight_text(shown, max_len=0) == shown
        return shown

    expected = clean(0)
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(clean, range(3))) == [expected] * 3
    workspace, home = tmp_path / "ws", tmp_path / "home"
    workspace.mkdir()
    (workspace / "app.py").write_text("pass\n", encoding="utf-8")
    for _ in range(2):
        row = add_insight(workspace, source, paths=["app.py"], home=home)
        assert body[:4] not in row["text"]
    assert all(body[:4] not in row["text"] for row in read_insight_rows(workspace, home=home))


@pytest.mark.parametrize("bounded", [False, True], ids=["short", "bounded"])
@pytest.mark.parametrize("order", ["family-first", "entropy-first", "family-middle"])
@pytest.mark.parametrize("control", ["\r", "\x85", "\x1b[31m"], ids=["cr", "nel", "csi"])
def test_round8_overlap_preserves_every_detector_byte(tmp_path, bounded, order, control):
    from concurrent.futures import ThreadPoolExecutor

    from aegis_core.insights import add_insight, read_insight_rows
    from aegis_core.proposals.model import clean_text
    from aegis_core.redaction import redact_insight_text

    entropy = "aB1cD2eF3gH4iJ5kL6mN7oP8"
    family = "AK" + "IA" + control + "ABCDEFGHIJKLMNOP"
    value = {"family-first": family + entropy,
             "entropy-first": entropy + control + family,
             "family-middle": entropy + control + family + entropy}[order]
    source = value + (" safe " + "note " * 1000 if bounded else "")

    def clean(_index):
        events = []
        shown = redact_insight_text(source, max_len=0, on_replacements=events.append)
        assert "[REDACTED_AWS]" in shown
        assert len(events) == 1
        assert not any(entropy[index:index + 4] in shown for index in range(len(entropy) - 3))
        cursor = 0
        for batch in events:
            for start, end, replacement in batch:
                assert cursor <= start < end <= min(len(source), 4097)
                assert entropy not in replacement
                cursor = end
        assert redact_insight_text(shown, max_len=0) == shown
        return shown

    expected = clean(0)
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(clean, range(3))) == [expected] * 3
    assert entropy[:4] not in clean_text(value, 300)
    workspace, home = tmp_path / "ws", tmp_path / "home"
    workspace.mkdir()
    (workspace / "app.py").write_text("pass\n", encoding="utf-8")
    for _ in range(2):
        add_insight(workspace, source, paths=["app.py"], kind=value, home=home)
    stored = read_insight_rows(workspace, home=home)
    assert all(entropy[:4] not in row[field] for row in stored for field in ("text", "kind"))


@pytest.mark.parametrize("prefix", ["", "person.", "/home/"])
@pytest.mark.parametrize("bounded", [False, True])
def test_round8_privacy_overlap_and_existing_masks_are_stable(prefix, bounded):
    from aegis_core.redaction import redact_insight_text

    credential = "gh" + "p_" + "a" * 36
    value = prefix + credential + ("@example.test" if prefix != "/home/" else "/file")
    if bounded:
        value += " safe " + "note " * 1000
    shown = redact_insight_text(value, max_len=0)
    assert "[REDACTED_VCS_TOKEN]" in shown
    assert "aaaa" not in shown
    if prefix != "/home/":
        # ROUND-8c: overlapping privacy leaves known-secret context intact.
        assert shown.startswith(prefix + "[REDACTED_VCS_TOKEN]@example.test")
        assert "[REDACTED_EMAIL]" not in shown
    for _ in range(2):
        events = []
        assert redact_insight_text(shown, max_len=0, on_replacements=events.append) == shown
        assert events == []


@pytest.mark.parametrize("control", ["", "\r", "\x85", "\x1b[1:2m", "\x9b31m"],
                         ids=["plain", "cr", "nel", "esc", "c1"])
@pytest.mark.parametrize("bounded", [False, True])
@pytest.mark.parametrize("shape", ["email", "home", "ip", "disjoint"])
def test_round8c_privacy_context_and_secret_material_keep_distinct_coverage(tmp_path, control, bounded, shape):
    from concurrent.futures import ThreadPoolExecutor
    from aegis_core.insights import add_insight, read_insight_rows
    from aegis_core.redaction import redact_insight_text

    key = "gh" + "p_" + "a" * 10 + control + "a" * 26
    value, expected = {
        "email": ("person." + key + "@example.test", "person.[REDACTED_VCS_TOKEN]@example.test"),
        "home": ("/home/person." + key + ".vault/file", "/home/person.[REDACTED_VCS_TOKEN].vault/file"),
        "ip": ("token=10." + control + "20.30.40", "token=[REDACTED]"),
        "disjoint": ("person@example.test " + key + " /home/alice 10.20.30.40",
                     "[REDACTED_EMAIL] [REDACTED_VCS_TOKEN] /home/~user [REDACTED_IP]"),
    }[shape]
    source = value + (" safe " + "note " * 1000 if bounded else "")

    def clean(_index):
        events = []
        shown = redact_insight_text(source, max_len=0, on_replacements=events.append)
        assert shown.startswith(expected)
        if not bounded:
            assert shown == expected
        assert len(events) == 1
        assert "aaaa" not in shown
        cursor = 0
        for batch in events:
            for start, end, payload in batch:
                assert cursor <= start < end <= min(len(source), 4097)
                cursor = end
        assert redact_insight_text(shown, max_len=0) == shown
        return shown

    def fail(_events):
        raise RuntimeError("observer failed")

    for _ in range(2):
        with pytest.raises(RuntimeError, match="^observer failed$"):
            redact_insight_text(source, max_len=0, on_replacements=fail)
    shown = clean(0)
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(clean, range(3))) == [shown] * 3
    workspace, home = tmp_path / "ws", tmp_path / "home"
    workspace.mkdir()
    (workspace / "app.py").write_text("pass\n", encoding="utf-8")
    for _ in range(2):
        row = add_insight(workspace, value, kind=value, paths=["app.py"], home=home)
        assert row["text"] == expected and row["kind"] == expected
    assert all(row["text"] == expected for row in read_insight_rows(workspace, home=home))


@pytest.mark.parametrize("name", ["extra_spans", "protected_spans"])
@pytest.mark.parametrize("spans", [((0, 1, "x" * 129),), ((0, 1, "x"),) * 129])
def test_round8_span_budgets_refuse_before_detection_then_retry(monkeypatch, name, spans):
    from aegis_core.redaction import RedactionRefusal

    original = primitives._display_secret_spans

    def forbidden(*args, **kwargs):
        pytest.fail("oversized span metadata reached detection")

    monkeypatch.setattr("aegis_core.primitives._display_secret_spans", forbidden)
    for _ in range(2):
        with pytest.raises(RedactionRefusal, match="^too_large$"):
            primitives.redact_display_secrets("safe", limit=4, **{name: spans})
    monkeypatch.setattr("aegis_core.primitives._display_secret_spans", original)
    assert primitives.redact_display_secrets("safe", limit=4) == "safe"


@pytest.mark.parametrize("family,value,secret,marker", _round8_credential_families())
@pytest.mark.parametrize("intro", ["\x1b[", "\x9b"], ids=["esc", "c1"])
@pytest.mark.parametrize("header", ["m", "1;2m", "1:2m", "1:2 !p"], ids=["empty", "semicolon", "colon", "intermediate"])
def test_round8_complete_csi_detection_keeps_original_coordinates(tmp_path, family, value, secret, marker, intro, header):
    from concurrent.futures import ThreadPoolExecutor
    from aegis_core.insights import add_insight, read_insight_rows
    from aegis_core.proposals.model import clean_text
    from aegis_core.redaction import redact_insight_text

    split = max(1, len(secret) // 2)
    joined = secret[:split] + intro + header + secret[split:]
    source = value.replace(secret, joined, 1)
    events = []
    shown = redact_insight_text(source, max_len=0, on_replacements=events.append)
    assert marker in shown and secret[:4] not in shown
    assert len(events) == 1
    cursor = 0
    for start, end, payload in events[0]:
        assert cursor <= start < end <= len(source)
        cursor = end
    assert redact_insight_text(shown, max_len=0) == shown
    assert secret[:4] not in clean_text(source, 4096)
    benign = "ordinary" + intro + header + " note"
    assert redact_insight_text(benign, max_len=0) == benign
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(lambda _: redact_insight_text(source, max_len=0), range(3))) == [shown] * 3
    workspace = tmp_path / "ws"
    workspace.mkdir()
    for _ in range(2):
        add_insight(workspace, source, paths=[], home=tmp_path / "home")
    assert all(secret[:4] not in row["text"] for row in read_insight_rows(workspace, home=tmp_path / "home"))


@pytest.mark.parametrize("control", ["\r", "\x85", "\x1b[1:2m", "\x9b31m"], ids=["cr", "nel", "esc", "c1"])
@pytest.mark.parametrize("value,split,body", [
    ("k7Qm9pL2xV4nR8wY3tB6cD1fH0aZ", 16, "k7Qm"),
    ("person@example.test", 3, "pers"),
    ("10.20.30.40", 5, "10.2"),
    ("/home/person", 8, "pers"),
])
@pytest.mark.parametrize("bounded", [False, True])
def test_round8_entropy_and_privacy_scan_every_display_view(tmp_path, control, value, split, body, bounded):
    from concurrent.futures import ThreadPoolExecutor
    from aegis_core.insights import add_insight, read_insight_rows
    from aegis_core.proposals.model import clean_text, ProposalError
    from aegis_core.redaction import redact_insight_text

    source = value[:split] + control + value[split:] + (" note" * 1000 if bounded else "")
    events = []
    shown = redact_insight_text(source, max_len=0, on_replacements=events.append)
    assert body not in shown
    assert len(events) == 1
    if bounded:
        with pytest.raises(ProposalError) as refusal:
            clean_text(source, 300)
        assert refusal.value.code == "too_large"
    else:
        assert body not in clean_text(source, 300)
    assert redact_insight_text(shown, max_len=0) == shown
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(lambda _: redact_insight_text(source, max_len=0), range(3))) == [shown] * 3
    workspace = tmp_path / "ws"
    workspace.mkdir()
    for _ in range(2):
        add_insight(workspace, source, paths=[], home=tmp_path / "home")
    assert all(body not in row["text"] for row in read_insight_rows(workspace, home=tmp_path / "home"))


# Bind after all definitions: the shared table imports these callables for replay,
# and either test module must also be importable first. Only layout/label metadata
# lives beside the table; every original argument comes from CORPUS_CASES.
from tests.unit.core.test_display_attribution_dense import parametrize_original

test_display_escape_boundaries_mask_secrets_on_every_surface = parametrize_original(
    test_display_escape_boundaries_mask_secrets_on_every_surface)
test_display_removed_controls_preserve_secret_boundaries = parametrize_original(
    test_display_removed_controls_preserve_secret_boundaries)
test_display_ten_million_removed_controls_do_not_build_per_control_state = parametrize_original(
    test_display_ten_million_removed_controls_do_not_build_per_control_state)
test_display_boundary_detection_uses_shared_secret_families = parametrize_original(
    test_display_boundary_detection_uses_shared_secret_families)
test_display_provenance_masks_low_entropy_keys_after_every_header = parametrize_original(
    test_display_provenance_masks_low_entropy_keys_after_every_header)
test_display_provenance_masks_overlaps_inside_an_ordinary_match = parametrize_original(
    test_display_provenance_masks_overlaps_inside_an_ordinary_match)
test_display_provenance_covers_every_string_form_and_header = parametrize_original(
    test_display_provenance_covers_every_string_form_and_header)
test_display_provenance_overlaps_and_headers_are_independent_in_threads = parametrize_original(
    test_display_provenance_overlaps_and_headers_are_independent_in_threads)
test_display_source_view_masks_credentials_partly_consumed_by_csi = parametrize_original(
    test_display_source_view_masks_credentials_partly_consumed_by_csi)
test_display_source_view_keeps_header_state_across_ignored_controls = parametrize_original(
    test_display_source_view_keeps_header_state_across_ignored_controls)
test_display_source_view_accepts_control_only_nonsecret_text = parametrize_original(
    test_display_source_view_accepts_control_only_nonsecret_text)
test_display_deleted_view_masks_consumed_prefix_with_internal_control = parametrize_original(
    test_display_deleted_view_masks_consumed_prefix_with_internal_control)
test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers = parametrize_original(
    test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers)
test_display_deleted_view_preserves_bel_termination_and_nonsecret_parity = parametrize_original(
    test_display_deleted_view_preserves_bel_termination_and_nonsecret_parity)
test_display_renderer_provenance_keeps_control_interrupted_headers = parametrize_original(
    test_display_renderer_provenance_keeps_control_interrupted_headers)
test_display_renderer_provenance_recovers_consumed_credential_label = parametrize_original(
    test_display_renderer_provenance_recovers_consumed_credential_label)
test_display_pem_extents_cover_differently_labelled_nested_body = parametrize_original(
    test_display_pem_extents_cover_differently_labelled_nested_body)
test_display_source_segments_seal_suppressed_strings = parametrize_original(
    test_display_source_segments_seal_suppressed_strings)
test_display_source_segments_do_not_invent_credential_whitespace = parametrize_original(
    test_display_source_segments_do_not_invent_credential_whitespace)
test_display_source_segments_do_not_join_visible_context_through_hidden_payload = parametrize_original(
    test_display_source_segments_do_not_join_visible_context_through_hidden_payload)
test_display_source_segments_still_mask_visible_secrets_on_both_sides = parametrize_original(
    test_display_source_segments_still_mask_visible_secrets_on_both_sides)
test_display_source_segments_keep_prefixed_secret_context_detectable = parametrize_original(
    test_display_source_segments_keep_prefixed_secret_context_detectable)
test_display_rendered_segments_seal_hidden_token_prefix = parametrize_original(
    test_display_rendered_segments_seal_hidden_token_prefix)
test_display_rendered_segments_preserve_visible_space_inside_nonsecret = parametrize_original(
    test_display_rendered_segments_preserve_visible_space_inside_nonsecret)
test_display_rendered_segments_still_join_fully_removed_controls = parametrize_original(
    test_display_rendered_segments_still_join_fully_removed_controls)
test_display_rendered_segments_keep_visible_credential_whitespace = parametrize_original(
    test_display_rendered_segments_keep_visible_credential_whitespace)
test_display_reassembled_tokens_use_markers_before_caller_redaction = parametrize_original(
    test_display_reassembled_tokens_use_markers_before_caller_redaction)
test_display_unions_canonical_and_source_only_masks = parametrize_original(
    test_display_unions_canonical_and_source_only_masks)
test_display_does_not_orphan_value_after_guarding_secret_key_context = parametrize_original(
    test_display_does_not_orphan_value_after_guarding_secret_key_context)
test_display_restored_union_masks_before_boundary_changes_or_clipping = parametrize_original(
    test_display_restored_union_masks_before_boundary_changes_or_clipping)
test_display_source_guard_cannot_complete_a_new_credential_or_tear_a_mask = parametrize_original(
    test_display_source_guard_cannot_complete_a_new_credential_or_tear_a_mask)
test_display_attribution_preserves_ordinary_left_boundary = parametrize_original(
    test_display_attribution_preserves_ordinary_left_boundary)
test_display_attribution_covers_shared_rule_families = parametrize_original(
    test_display_attribution_covers_shared_rule_families)
test_display_attribution_long_benign_colour_runs_keep_parity = parametrize_original(
    test_display_attribution_long_benign_colour_runs_keep_parity)
test_display_attribution_detection_windows_span_removed_control_gaps = parametrize_original(
    test_display_attribution_detection_windows_span_removed_control_gaps)
test_display_attribution_masks_overlapping_ordinary_credentials = parametrize_original(
    test_display_attribution_masks_overlapping_ordinary_credentials)
test_display_attribution_fallback_preserves_ordinary_boundary_and_flags = parametrize_original(
    test_display_attribution_fallback_preserves_ordinary_boundary_and_flags)
test_display_attribution_fallback_keeps_carried_starts = parametrize_original(
    test_display_attribution_fallback_keeps_carried_starts)
