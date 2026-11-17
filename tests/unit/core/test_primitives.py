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


# Display parity and redaction share boundaries even when legacy output keeps a kind byte.
@pytest.mark.parametrize("prefix", [
    pytest.param("\x1bP", id="dcs"),
    pytest.param("\x1bP\x1b[31m", id="dcs-csi"),
    pytest.param("note\x1b]\x1bP", id="osc-dcs"),
    pytest.param("note\x1b]0;title\x1b7", id="osc-title-esc7"),
    pytest.param("\x1bP\x9b31m", id="dcs-c1-csi"),
    pytest.param("\x1bP$q", id="dcs-intermediate-header"),
    pytest.param("\x1bP1;2q", id="dcs-parameter-header"),
    pytest.param("\x901;2q", id="c1-dcs-parameter-header"),
    pytest.param("\x1b(B", id="escape-intermediate-header"),
    *[pytest.param("note\x1b" + kind, id="esc-" + kind) for kind in "NOM78c"],
    pytest.param("\x1bX", id="sos"),
    pytest.param("\x1b^", id="pm"),
    pytest.param("\x1b_", id="apc"),
    pytest.param("note\x1b?", id="unknown-escape"),
    pytest.param("note\x1b[12;\x00", id="abandoned-csi"),
])
@pytest.mark.parametrize("surface", ["sanitize", "receipt", "guidance"])
def test_display_escape_boundaries_mask_secrets_on_every_surface(prefix, surface):
    from aegis_core import diagnostic_messages
    from aegis_core.redaction import redact_command_secrets

    key = "AK" + "IA" + "IOSFODNN7EXAMPLE"
    render = {"sanitize": lambda value: redact_command_secrets(primitives.sanitize_display(value, max_len=None)),
              "receipt": diagnostic_messages.receipt_value,
              "guidance": diagnostic_messages.guidance_value}[surface]
    for _ in range(2):
        shown = render(prefix + key)
        assert key not in shown
        assert "REDACTED" in shown


@pytest.mark.parametrize("code", [code for code in (*range(32), *range(127, 160)) if code != 27])
def test_display_removed_controls_preserve_secret_boundaries(code):
    from aegis_core import diagnostic_messages
    from aegis_core.redaction import redact_command_secrets

    key = "AK" + "IA" + "IOSFODNN7EXAMPLE"
    value = "note" + chr(code) + key
    for shown in (redact_command_secrets(primitives.sanitize_display(value, max_len=None)),
                  diagnostic_messages.receipt_value(value), diagnostic_messages.guidance_value(value)):
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


def test_display_boundaries_are_local_to_parallel_calls_and_retries():
    from concurrent.futures import ThreadPoolExecutor

    key = "AK" + "IA" + "IOSFODNN7EXAMPLE"
    values = ["\x1bP" + key, "missing\x1b]FORGED", "plain " + key] * 12
    expected = ["P[REDACTED_AWS]", "missing]FORGED", "plain " + key] * 12
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(lambda value: primitives.sanitize_display(value, max_len=None), values)) == expected
    assert [primitives.sanitize_display(value, max_len=None) for value in values] == expected


@pytest.mark.parametrize("tail", ["", "safe", "secret"])
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


@pytest.mark.parametrize("value, payload", [
    ("AS" + "IA" + "A" * 16, "A" * 16),
    ("gh" + "p_" + "a" * 36, "a" * 36),
    ("sk" + "-proj-" + "Ab1" * 12, "Ab1" * 12),
    ("token=" + "test-value-123456", "test-value-123456"),
    ("Bearer " + "a" * 20, "a" * 20),
    ("https://user:" + "test-value-123456" + "@example.test", "test-value-123456"),
    ("-----BEGIN " + "PRIVATE KEY-----body", "body"),
])
def test_display_boundary_detection_uses_shared_secret_families(value, payload):
    from aegis_core import diagnostic_messages
    from aegis_core.redaction import redact_command_secrets

    for shown in (redact_command_secrets(primitives.sanitize_display("note\x1bP" + value, max_len=None)),
                  diagnostic_messages.receipt_value("note\x1bP" + value),
                  diagnostic_messages.guidance_value("note\x1bP" + value)):
        assert payload not in shown
        assert "REDACTED" in shown


def test_display_preserves_url_context_and_masks_overlapping_secret_rules():
    value = "https://user:" + "test-value-123456" + "@example.test"
    assert primitives.sanitize_display("note\x1bP" + value, max_len=None) == (
        "notePhttps://user:[REDACTED]@example.test")
    key = "AK" + "IA" + "IOSFODNN7EXAMPLE"
    shown = primitives.sanitize_display("note\x1bPtoken=" + key, max_len=None)
    assert shown.startswith("notePtoken=")
    assert key not in shown and "REDACTED" in shown


@pytest.mark.parametrize("prefix", [
    pytest.param("\x1b(0", id="esc-numeric-final"),
    pytest.param("\x1b[1:2m", id="csi-colon-final"),
    pytest.param("\x1b[1$m", id="csi-intermediate-final"),
    pytest.param("\x1bP1", id="dcs-parameters"),
    pytest.param("\x1b]\x1bP1", id="nested-dcs-parameters"),
    pytest.param("\x901", id="c1-dcs-parameters"),
    pytest.param("\x9b1", id="c1-csi-parameters"),
    pytest.param("\x1b[1:2", id="unsupported-csi-parameters"),
    pytest.param("\x1b]1", id="osc-parameters"),
    pytest.param("\x9d1", id="c1-osc-parameters"),
])
@pytest.mark.parametrize("surface", ["sanitize", "receipt", "guidance"])
def test_display_provenance_masks_low_entropy_keys_after_every_header(prefix, surface):
    from aegis_core import diagnostic_messages
    from aegis_core.redaction import redact_command_secrets

    key = "AK" + "IA" + "A" * 16
    render = {"sanitize": lambda value: redact_command_secrets(primitives.sanitize_display(value, max_len=None)),
              "receipt": diagnostic_messages.receipt_value,
              "guidance": diagnostic_messages.guidance_value}[surface]
    for _ in range(2):
        shown = render(prefix + key)
        assert "A" * 16 not in shown
        assert "REDACTED" in shown


@pytest.mark.parametrize("family", ["aws", "github"])
@pytest.mark.parametrize("surface", ["sanitize", "receipt", "guidance"])
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
              "guidance": diagnostic_messages.guidance_value}[surface]
    for _ in range(2):
        shown = render(first + "\r" + second)
        assert all(payload not in shown for payload in payloads)
        assert "REDACTED" in shown


@pytest.mark.parametrize("introducer", ["\x1bP", "\x1b]", "\x1bX", "\x1b^", "\x1b_",
                                         "\x90", "\x98", "\x9d", "\x9e", "\x9f"])
@pytest.mark.parametrize("header", ["1", "1:2", "1 $"])
@pytest.mark.parametrize("surface", ["sanitize", "receipt", "guidance"])
def test_display_provenance_covers_every_string_form_and_header(introducer, header, surface):
    from aegis_core import diagnostic_messages
    from aegis_core.redaction import redact_command_secrets

    key = "AK" + "IA" + "A" * 16
    render = {"sanitize": lambda value: redact_command_secrets(primitives.sanitize_display(value, max_len=None)),
              "receipt": diagnostic_messages.receipt_value,
              "guidance": diagnostic_messages.guidance_value}[surface]
    shown = render(introducer + header + key)
    assert "A" * 16 not in shown
    assert "REDACTED" in shown


@pytest.mark.parametrize("surface", ["sanitize", "receipt", "guidance"])
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
              "guidance": diagnostic_messages.guidance_value}[surface]
    with ThreadPoolExecutor(max_workers=3) as pool:
        shown = list(pool.map(render, values))
    assert all("REDACTED" in value for value in shown)
    assert all(payload not in value for value in shown for payload in ("A" * 16, "B" * 12, "a" * 20))
    assert render("missing\x1b]FORGED") == render("missing]FORGED")


@pytest.mark.parametrize("prefix", ["\x1b[", "\x1b[1"])
@pytest.mark.parametrize("family", ["aws", "github"])
@pytest.mark.parametrize("surface", ["sanitize", "receipt", "guidance"])
def test_display_source_view_masks_credentials_partly_consumed_by_csi(prefix, family, surface):
    from aegis_core import diagnostic_messages
    from aegis_core.redaction import redact_command_secrets

    key, payload = (("AK" + "IA" + "A" * 16, "A" * 16) if family == "aws" else
                    ("gh" + "p_" + "a" * 36, "a" * 36))
    render = {"sanitize": lambda value: redact_command_secrets(primitives.sanitize_display(value, max_len=None)),
              "receipt": diagnostic_messages.receipt_value,
              "guidance": diagnostic_messages.guidance_value}[surface]
    shown = render(prefix + key)
    assert payload not in shown
    assert "REDACTED" in shown
    assert shown == render("[REDACTED_AWS]" if family == "aws" else "[REDACTED_VCS_TOKEN]")


@pytest.mark.parametrize("prefix", [
    *[pytest.param(introducer + "1\x002", id=name) for name, introducer in (
        ("dcs", "\x1bP"), ("osc", "\x1b]"), ("sos", "\x1bX"), ("pm", "\x1b^"), ("apc", "\x1b_"),
        ("c1-dcs", "\x90"), ("c1-osc", "\x9d"), ("c1-sos", "\x98"), ("c1-pm", "\x9e"), ("c1-apc", "\x9f"))],
    pytest.param("\x1b(\x000", id="esc-intermediate"),
    pytest.param("\x1b[1:\x002m", id="csi-subparameter"),
    pytest.param("\x9b1:\x002m", id="c1-csi-subparameter"),
    pytest.param("\x1b[1\x002m", id="csi-parameter"),
])
@pytest.mark.parametrize("surface", ["sanitize", "receipt", "guidance"])
@pytest.mark.parametrize("control", ["\x00", "\x08", "\x0b", "\r", "\x11", "\x19", "\x7f", "\x85", "\x91", "\x99"])
def test_display_source_view_keeps_header_state_across_ignored_controls(prefix, surface, control):
    from aegis_core import diagnostic_messages
    from aegis_core.redaction import redact_command_secrets

    key = "AK" + "IA" + "A" * 16
    render = {"sanitize": lambda value: redact_command_secrets(primitives.sanitize_display(value, max_len=None)),
              "receipt": diagnostic_messages.receipt_value,
              "guidance": diagnostic_messages.guidance_value}[surface]
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


@pytest.mark.parametrize("value, expected", [("\n", " "), ("\t\r\x00", " "), ("\r\x00", "")])
def test_display_source_view_accepts_control_only_nonsecret_text(value, expected):
    assert primitives.sanitize_display(value, max_len=None) == expected


def test_display_source_view_masks_only_surviving_characters_and_preserves_context():
    key = "AK" + "IA" + "A" * 16
    assert primitives.sanitize_display("before\x1b]" + key + "\x07after", max_len=None) == "beforeafter"
    assert primitives.sanitize_display("before\x1b[1" + key + " after", max_len=None) == "before[REDACTED_AWS] after"
    head, tail = "-----BEGIN " + "PRIVATE KEY-----", "-----END " + "PRIVATE KEY-----"
    value = head + "outer\r" + head + "inner" + tail + "\r" + key
    assert primitives.sanitize_display(value, max_len=None) == "[REDACTED_PEM][REDACTED_AWS]"


@pytest.mark.parametrize("prefix", [pytest.param("\x1b[", id="csi"), pytest.param("\x1b[1", id="csi-parameter")])
@pytest.mark.parametrize("inner", [pytest.param("\r", id="cr"), pytest.param("\x00", id="nul"),
                                  pytest.param("\x7f", id="del"), pytest.param("\x85", id="c1"),
                                  pytest.param("\x1b[31m", id="supported-csi", marks=pytest.mark.xfail(
                                      strict=True, reason="SANITIZE-CRAFTED-INTERLEAVING"))])
@pytest.mark.parametrize("family", ["aws", "github"])
@pytest.mark.parametrize("surface", ["sanitize", "receipt", "guidance"])
def test_display_deleted_view_masks_consumed_prefix_with_internal_control(prefix, inner, family, surface):
    from aegis_core import diagnostic_messages
    from aegis_core.redaction import redact_command_secrets

    key = "AK" + "IA" + "A" * 16 if family == "aws" else "gh" + "p_" + "a" * 36
    render = {"sanitize": lambda value: redact_command_secrets(primitives.sanitize_display(value, max_len=None)),
              "receipt": diagnostic_messages.receipt_value,
              "guidance": diagnostic_messages.guidance_value}[surface]
    shown = render(prefix + key[:4] + inner + key[4:])
    assert shown == render("[REDACTED_AWS]" if family == "aws" else "[REDACTED_VCS_TOKEN]")


@pytest.mark.parametrize("prefix", [
    pytest.param("\x1b[?\x07:m", id="csi"), pytest.param("\x9b?\x07:m", id="c1-csi"),
    pytest.param("\x1b(\x07B", id="esc-intermediate"),
    *[pytest.param(introducer + "1\x072", id=name) for name, introducer in (
        ("sos", "\x1bX"), ("pm", "\x1b^"), ("apc", "\x1b_"),
        ("c1-sos", "\x98"), ("c1-pm", "\x9e"), ("c1-apc", "\x9f"),
        ("c1-dcs", "\x90"), ("c1-osc", "\x9d"))],
])
@pytest.mark.parametrize("surface", ["sanitize", "receipt", "guidance"])
def test_display_deleted_view_keeps_bel_transparent_in_nonterminating_headers(prefix, surface):
    from aegis_core import diagnostic_messages
    from aegis_core.redaction import redact_command_secrets

    key = "AK" + "IA" + "A" * 16
    render = {"sanitize": lambda value: redact_command_secrets(primitives.sanitize_display(value, max_len=None)),
              "receipt": diagnostic_messages.receipt_value,
              "guidance": diagnostic_messages.guidance_value}[surface]
    shown = render(prefix + key)
    assert "A" * 16 not in shown
    assert "REDACTED" in shown


@pytest.mark.parametrize("introducer", ["\x1b]", "\x1bP"])
def test_display_deleted_view_preserves_bel_termination_and_nonsecret_parity(introducer):
    key = "AK" + "IA" + "A" * 16
    assert primitives.sanitize_display("before" + introducer + key + "\x07after", max_len=None) == "beforeafter"
    assert primitives.sanitize_display("before" + introducer + "1\x072safe", max_len=None) == "before2safe"


@pytest.mark.parametrize("control", [pytest.param("\x07", id="bel"), pytest.param("\t", id="tab"),
                                    pytest.param("\n", id="lf")])
@pytest.mark.parametrize("header", ["\x1b[", "\x9b", "\x1b("])
@pytest.mark.parametrize("surface", ["sanitize", "receipt", "guidance"])
def test_display_renderer_provenance_keeps_control_interrupted_headers(control, header, surface):
    from aegis_core import diagnostic_messages
    from aegis_core.redaction import redact_command_secrets

    key = "AK" + "IA" + "A" * 16
    render = {"sanitize": lambda value: redact_command_secrets(primitives.sanitize_display(value, max_len=None)),
              "receipt": diagnostic_messages.receipt_value,
              "guidance": diagnostic_messages.guidance_value}[surface]
    shown = render(header + control + ("B" if header.endswith("(") else "m") + key)
    assert "A" * 16 not in shown
    assert "REDACTED" in shown


@pytest.mark.parametrize("surface", ["sanitize", "receipt", "guidance"])
def test_display_renderer_provenance_recovers_consumed_credential_label(surface):
    from aegis_core import diagnostic_messages
    from aegis_core.redaction import redact_command_secrets

    render = {"sanitize": lambda value: redact_command_secrets(primitives.sanitize_display(value, max_len=None)),
              "receipt": diagnostic_messages.receipt_value,
              "guidance": diagnostic_messages.guidance_value}[surface]
    shown = render("\x1bcredential=ab\rcdefgh")
    assert "abcdefgh" not in shown
    assert "REDACTED" in shown


@pytest.mark.parametrize("surface", ["sanitize", "receipt", "guidance"])
@pytest.mark.parametrize("label", ["EC", "OPENSSH"])
def test_display_pem_extents_cover_differently_labelled_nested_body(surface, label):
    from aegis_core import diagnostic_messages
    from aegis_core.redaction import redact_command_secrets

    def head(value):
        return "-----BEGIN " + value + " PRIVATE KEY-----"

    value = head("RSA") + "\r" + head(label) + "-----END RSA PRIVATE KEY-----privatepayload"
    render = {"sanitize": lambda value: redact_command_secrets(primitives.sanitize_display(value, max_len=None)),
              "receipt": diagnostic_messages.receipt_value,
              "guidance": diagnostic_messages.guidance_value}[surface]
    shown = render(value)
    assert "privatepayload" not in shown
    assert "REDACTED" in shown


@pytest.mark.parametrize("introducer", [pytest.param("\x1b]", id="osc"), pytest.param("\x1bP", id="dcs")])
@pytest.mark.parametrize("terminator", [pytest.param("\x07", id="bel"), pytest.param("\x1b\\", id="st")])
@pytest.mark.parametrize("hidden, tail", [("token=", "after"), ("Bearer", "after_sixteen_chars"),
                                         ("-----BEGIN " + "PRIVATE KEY-----", "after")])
@pytest.mark.parametrize("surface", ["sanitize", "receipt", "guidance"])
def test_display_source_segments_seal_suppressed_strings(introducer, terminator, hidden, tail, surface):
    from aegis_core import diagnostic_messages
    from aegis_core.redaction import redact_command_secrets

    render = {"sanitize": lambda value: redact_command_secrets(primitives.sanitize_display(value, max_len=None)),
              "receipt": diagnostic_messages.receipt_value,
              "guidance": diagnostic_messages.guidance_value}[surface]
    assert render("before" + introducer + "0;" + hidden + terminator + tail) == render("before" + tail)


@pytest.mark.parametrize("control", [pytest.param("\x00", id="nul"), pytest.param("\r", id="cr"),
                                    pytest.param("\x7f", id="del"), pytest.param("\x85", id="c1")])
@pytest.mark.parametrize("head, tail", [("Bearer", "anything_sixteen_chars"), ("password", "is abcdefgh")])
@pytest.mark.parametrize("surface", ["sanitize", "receipt", "guidance"])
def test_display_source_segments_do_not_invent_credential_whitespace(control, head, tail, surface):
    from aegis_core import diagnostic_messages
    from aegis_core.redaction import redact_command_secrets

    render = {"sanitize": lambda value: redact_command_secrets(primitives.sanitize_display(value, max_len=None)),
              "receipt": diagnostic_messages.receipt_value,
              "guidance": diagnostic_messages.guidance_value}[surface]
    assert render(head + control + tail) == render(head + tail)


@pytest.mark.parametrize("introducer", [pytest.param("\x1b]", id="osc"), pytest.param("\x1bP", id="dcs")])
@pytest.mark.parametrize("terminator", [pytest.param("\x07", id="bel"), pytest.param("\x1b\\", id="st")])
@pytest.mark.parametrize("surface", ["sanitize", "receipt", "guidance"])
def test_display_source_segments_do_not_join_visible_context_through_hidden_payload(introducer, terminator, surface):
    from aegis_core import diagnostic_messages
    from aegis_core.redaction import redact_command_secrets

    render = {"sanitize": lambda value: redact_command_secrets(primitives.sanitize_display(value, max_len=None)),
              "receipt": diagnostic_messages.receipt_value,
              "guidance": diagnostic_messages.guidance_value}[surface]
    assert render("token=" + introducer + "filler" + terminator + "abc") == render("token=abc")


@pytest.mark.parametrize("introducer", [pytest.param("\x1b]", id="osc"), pytest.param("\x1bP", id="dcs")])
@pytest.mark.parametrize("terminator", [pytest.param("\x07", id="bel"), pytest.param("\x1b\\", id="st")])
@pytest.mark.parametrize("surface", ["sanitize", "receipt", "guidance"])
def test_display_source_segments_still_mask_visible_secrets_on_both_sides(introducer, terminator, surface):
    from aegis_core import diagnostic_messages
    from aegis_core.redaction import redact_command_secrets

    key = "AK" + "IA" + "A" * 16
    render = {"sanitize": lambda value: redact_command_secrets(primitives.sanitize_display(value, max_len=None)),
              "receipt": diagnostic_messages.receipt_value,
              "guidance": diagnostic_messages.guidance_value}[surface]
    shown = render(key + introducer + "0;ordinary" + terminator + key)
    assert "A" * 16 not in shown
    assert "REDACTED" in shown


@pytest.mark.parametrize("value", ["service_password_name=" + "test-value-123456",
                                  "https://user:" + "test-value-123456" + "@example.test",
                                  "://user:" + "test-value-123456" + "@example.test"])
@pytest.mark.parametrize("surface", ["sanitize", "receipt", "guidance"])
def test_display_source_segments_keep_prefixed_secret_context_detectable(value, surface):
    from aegis_core import diagnostic_messages
    from aegis_core.redaction import redact_command_secrets

    render = {"sanitize": lambda value: redact_command_secrets(primitives.sanitize_display(value, max_len=None)),
              "receipt": diagnostic_messages.receipt_value,
              "guidance": diagnostic_messages.guidance_value}[surface]
    shown = render("note\x1bP" + value)
    assert "test-value-123456" not in shown
    assert "REDACTED" in shown


@pytest.mark.parametrize("introducer", [pytest.param("\x1b]", id="osc"), pytest.param("\x1bP", id="dcs")])
@pytest.mark.parametrize("terminator", [pytest.param("\x07", id="bel"), pytest.param("\x1b\\", id="st")])
@pytest.mark.parametrize("surface", ["sanitize", "receipt", "guidance"])
def test_display_rendered_segments_seal_hidden_token_prefix(introducer, terminator, surface):
    from aegis_core import diagnostic_messages
    from aegis_core.redaction import redact_command_secrets

    render = {"sanitize": lambda value: redact_command_secrets(primitives.sanitize_display(value, max_len=None)),
              "receipt": diagnostic_messages.receipt_value,
              "guidance": diagnostic_messages.guidance_value}[surface]
    value = "before" + introducer + "0;gh" + "p_" + terminator + "a" * 20
    assert render(value) == render("before" + "a" * 20)


@pytest.mark.parametrize("control", [pytest.param("\t", id="tab"), pytest.param("\n", id="lf")])
@pytest.mark.parametrize("surface", ["sanitize", "receipt", "guidance"])
def test_display_rendered_segments_preserve_visible_space_inside_nonsecret(control, surface):
    from aegis_core import diagnostic_messages
    from aegis_core.redaction import redact_command_secrets

    render = {"sanitize": lambda value: redact_command_secrets(primitives.sanitize_display(value, max_len=None)),
              "receipt": diagnostic_messages.receipt_value,
              "guidance": diagnostic_messages.guidance_value}[surface]
    assert render("AK" + "IA" + control + "A" * 16) == render("AK" + "IA " + "A" * 16)


@pytest.mark.parametrize("control", [pytest.param("\x00", id="nul"), pytest.param("\r", id="cr"),
                                    pytest.param("\x7f", id="del"), pytest.param("\x85", id="c1")])
@pytest.mark.parametrize("surface", ["sanitize", "receipt", "guidance"])
def test_display_rendered_segments_still_join_fully_removed_controls(control, surface):
    from aegis_core import diagnostic_messages
    from aegis_core.redaction import redact_command_secrets

    render = {"sanitize": lambda value: redact_command_secrets(primitives.sanitize_display(value, max_len=None)),
              "receipt": diagnostic_messages.receipt_value,
              "guidance": diagnostic_messages.guidance_value}[surface]
    shown = render("AK" + "IA" + control + "A" * 16)
    assert "A" * 16 not in shown
    assert "REDACTED" in shown


@pytest.mark.parametrize("prefix", [pytest.param("\x1b[", id="csi"), pytest.param("\x1b[1", id="csi-parameter")])
@pytest.mark.parametrize("control", [pytest.param("\t", id="tab"), pytest.param("\n", id="lf")])
@pytest.mark.parametrize("surface", ["sanitize", "receipt", "guidance"])
def test_display_rendered_segments_keep_visible_credential_whitespace(prefix, control, surface):
    from aegis_core import diagnostic_messages
    from aegis_core.redaction import redact_command_secrets

    render = {"sanitize": lambda value: redact_command_secrets(primitives.sanitize_display(value, max_len=None)),
              "receipt": diagnostic_messages.receipt_value,
              "guidance": diagnostic_messages.guidance_value}[surface]
    shown = render(prefix + "Bearer" + control + "a" * 20)
    assert "a" * 20 not in shown
    assert "REDACTED" in shown


@pytest.mark.parametrize("family", ["aws", "github"])
@pytest.mark.parametrize("removed", [pytest.param("\x1b[31m", id="sgr"), pytest.param("\r", id="cr"),
                                    pytest.param("\x00", id="nul")])
@pytest.mark.parametrize("prefix", [pytest.param("", id="plain"), pytest.param("\x1b[31m", id="color")])
def test_display_reassembled_tokens_use_markers_before_caller_redaction(family, removed, prefix):
    from aegis_core.redaction import redact_command_secrets

    key = "AK" + "IA" + "A" * 16 if family == "aws" else "gh" + "p_" + "a" * 36
    shown = primitives.sanitize_display(prefix + key[:2] + removed + key[2:], max_len=None)
    marker = "[REDACTED_AWS]" if family == "aws" else "[REDACTED_VCS_TOKEN]"
    assert shown == marker
    assert redact_command_secrets(shown) == marker


@pytest.mark.parametrize("family", ["aws", "github"])
def test_display_unions_canonical_and_source_only_masks(family):
    from aegis_core.redaction import redact_command_secrets

    key = "AK" + "IA" + "A" * 16 if family == "aws" else "gh" + "p_" + "a" * 36
    marker = "[REDACTED_AWS]" if family == "aws" else "[REDACTED_VCS_TOKEN]"
    value = "normal " + key + "; \x1bP1" + key
    shown = primitives.sanitize_display(value, max_len=None)
    assert shown == "normal " + marker + "; P1" + marker
    assert key not in redact_command_secrets(shown)


@pytest.mark.parametrize("surface", ["sanitize", "receipt", "guidance"])
def test_display_does_not_orphan_value_after_guarding_secret_key_context(surface):
    from aegis_core import diagnostic_messages
    from aegis_core.redaction import redact_command_secrets

    key = "gh" + "p_" + "token" + "a" * 20
    render = {"sanitize": lambda value: redact_command_secrets(primitives.sanitize_display(value, max_len=None)),
              "receipt": diagnostic_messages.receipt_value,
              "guidance": diagnostic_messages.guidance_value}[surface]
    shown = render("note\x1bP" + key + "=unrelated-value-4321")
    assert "a" * 20 not in shown
    assert "unrelated-value-4321" not in shown
    assert "REDACTED" in shown


@pytest.mark.parametrize("surface", ["sanitize", "receipt", "guidance"])
@pytest.mark.parametrize("case", ["changed-boundary", "ordered-coverage", "finite-clip"])
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
              "guidance": lambda text: diagnostic_messages.guidance_value(text, 400)}[surface]
    shown = render(value)
    assert key not in shown and key[:19] not in shown
    assert token not in shown and "bbbb" not in shown
    assert "REDACTED" in shown


@pytest.mark.parametrize("surface", ["sanitize", "receipt", "guidance"])
def test_display_source_guard_cannot_complete_a_new_credential_or_tear_a_mask(surface):
    from aegis_core import diagnostic_messages
    from aegis_core.redaction import redact_command_secrets

    value = "AK" + "IA" + "123456789PWD" + "\x1b=abcd"
    render = {"sanitize": lambda text: redact_command_secrets(primitives.sanitize_display(text, max_len=None)),
              "receipt": diagnostic_messages.receipt_value,
              "guidance": diagnostic_messages.guidance_value}[surface]
    shown = render(value)
    assert "abcd" not in shown and "omitted" not in shown
    expected = "AK" + "IA" + "123456789PWD"
    assert shown == expected + (r"\x5bREDACTED\x5d" if surface == "guidance" else "[REDACTED]")
