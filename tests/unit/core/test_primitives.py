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

@POSIX_ONLY
@pytest.mark.parametrize("zone", ["America/New_York", "Asia/Tokyo"])
def test_a_naive_datetime_is_utc_in_every_time_zone(monkeypatch, zone):
    monkeypatch.setenv("TZ", zone)
    time.tzset()
    try:
        assert utc_stamp(datetime(2026, 10, 19, 12, 0)) == "2026-10-19T12:00:00Z"
    finally:
        monkeypatch.undo()
        time.tzset()


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
    from aegis_cli import doctor, install_hosts  # doctor first: doctor_repair is loaded through it
    from aegis_cli import doctor_repair
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
    entry = doctor_repair._parse_json(doctor_repair._File(host, raw=host.read_bytes()))
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
