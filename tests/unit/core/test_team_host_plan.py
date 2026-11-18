"""Host-plan public parity, refusal mapping, retry and descriptor confinement."""
from contextlib import contextmanager
import json
import os
from pathlib import Path

import pytest

from conftest import symlink_or_skip
from aegis_core import team_host_plan as core
from aegis_core.team_host_registry import HostRefusal
from tools import hierarchy_hosts as legacy


def plan():
    return legacy.plan_record("alpha", legacy.CODEX, legacy.CLAUDE,
                              {"alpha/front-door": legacy.NATIVE}, "a" * 64)


def make_store(tmp_path):
    if not core.descriptor_supported():
        pytest.skip("descriptor-relative no-follow storage required")
    return tmp_path


def write_plan(root, value=None):
    path = root / core.PLAN_FILE
    path.write_text(json.dumps(plan() if value is None else value))
    return path


def snapshot(root):
    return {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}


@pytest.mark.parametrize("case,reason", [
    ("oversized", "too_large"), ("malformed", "invalid_json"),
    ("wrong_schema", "plan_schema"), ("unknown_key", "plan_keys"),
    ("missing_key", "plan_keys"), ("deep_json", "invalid_json"),
    ("invalid_utf8", "invalid_json"), ("duplicate", "invalid_json"),
])
def test_legacy_refusal_mapping_no_write_and_valid_retry(tmp_path, case, reason):
    root = make_store(tmp_path)
    original = plan()
    raw = {
        "oversized": b" " * 262145, "malformed": b"{",
        "wrong_schema": json.dumps(dict(original, schema="untrusted-marker")).encode(),
        "unknown_key": json.dumps(dict(original, untrusted_marker=True)).encode(),
        "missing_key": json.dumps({k: v for k, v in original.items() if k != "root"}).encode(),
        "deep_json": ("[" * 1200 + "0" + "]" * 1200).encode(),
        "invalid_utf8": bytes([255]), "duplicate": b'{"schema":1,"schema":2}',
    }[case]
    path = root / core.PLAN_FILE
    path.write_bytes(raw)
    legacy_errors = (ValueError, RecursionError) if case == "deep_json" else (ValueError,)
    with pytest.raises(legacy_errors):
        legacy.read_plan(root)
    before = snapshot(root)
    for _ in range(2):
        with pytest.raises(HostRefusal) as caught:
            core.read_plan(root)
        error = caught.value
        assert error.reason == reason
        assert error.code == 1 and error.next_action
        assert "untrusted-marker" not in str(error)
        assert snapshot(root) == before
    write_plan(root)
    assert core.read_plan(root) == legacy.read_plan(root) == original


def test_successful_pure_values_and_records_match_legacy(tmp_path):
    value = plan()
    assert core.plan_record("alpha", legacy.CODEX, legacy.CLAUDE,
                            value["stand_ins"], "a" * 64) == value
    assert core.validate_plan(value) == legacy.validate_plan(value)
    for endpoint in ("alpha/root", "alpha/lane/impl", "alpha/front-door", "beta/root"):
        assert core.plan_host(value, endpoint) == legacy.plan_host(value, endpoint)
    for host in legacy.HOST_KINDS:
        for stand_in in (True, False):
            assert core.team_start_mode(host, stand_in) == legacy.team_start_mode(host, stand_in)
    assert core.team_start_mode(legacy.CLAUDE, False, True) == "background"
    scope = legacy.qualify(legacy.CODEX, True)
    args = ("alpha/root", "root", legacy.CODEX, "exec", "session", 1, False, scope)
    assert core.session_record(*args) == legacy.session_record(*args)
    assert core.session_record_path(tmp_path, "alpha/root", 1) == legacy.session_record_path(
        tmp_path, "alpha/root", 1)
    assert core.require_binding(None, "untrusted-marker", "untrusted-marker", None) is None


def test_missing_and_governing_plans_match_legacy(tmp_path):
    root = make_store(tmp_path)
    assert core.read_plan(root) is legacy.read_plan(root) is None
    assert core.read_plan(root / "absent") is None
    other = root / "other"
    other.mkdir()
    write_plan(root)
    assert core.base_plan(root, "alpha") == legacy.base_plan(root, "alpha")
    assert core.governing_plan(other, root / "mailbox", "alpha") == legacy.governing_plan(
        other, root / "mailbox", "alpha")
    write_plan(other)
    assert core.governing_plan(other, root / "mailbox", "alpha") == plan()


def test_host_mismatch_is_fixed_no_write_and_valid_retry(tmp_path):
    value = plan()
    before = snapshot(tmp_path)
    with pytest.raises(ValueError):
        legacy.require_binding(value, "alpha/root", legacy.CLAUDE, False)
    for _ in range(2):
        with pytest.raises(HostRefusal) as caught:
            core.require_binding(value, "alpha/root", legacy.CLAUDE, False)
        assert caught.value.reason == "host_mismatch"
        assert caught.value.code == 1 and caught.value.next_action
        assert snapshot(tmp_path) == before
    assert core.require_binding(value, "alpha/root", legacy.CODEX, False) == legacy.require_binding(
        value, "alpha/root", legacy.CODEX, False)


def test_session_record_read_retry_and_mismatch(tmp_path):
    root = make_store(tmp_path)
    record = core.session_record("alpha/root", "root", legacy.CODEX, "exec", "session", 1,
                                 False, {"boundary": "reader"})
    path = core.session_record_path(root, "alpha/root", 1)
    assert core.session_recorded(path, record) is legacy.session_recorded(path, record) is False
    path.parent.mkdir()
    path.write_text(json.dumps(record))
    assert core.session_recorded(path, record) is legacy.session_recorded(path, record) is True
    before = snapshot(root)
    with pytest.raises(HostRefusal) as caught:
        core.session_recorded(path, dict(record, session="another"))
    assert caught.value.reason == "session_mismatch"
    assert snapshot(root) == before
    assert core.session_recorded(path, record)


def test_pure_path_length_exact_boundary_matches_legacy():
    assert core.MAX_PATH_CHARS == 32768
    root = "r" * 32768
    assert core.session_record_path(root, "alpha/root", 1) == legacy.session_record_path(root, "alpha/root", 1)
    with pytest.raises(HostRefusal) as caught:
        core.session_record_path(root + "r", "alpha/root", 1)
    assert caught.value.reason == "unsafe_path"
    assert caught.value.code == 1 and caught.value.next_action
    assert core.session_record_path(root, "alpha/root", 1) == legacy.session_record_path(root, "alpha/root", 1)


def test_plan_file_exact_byte_boundary_and_retry(tmp_path):
    root = make_store(tmp_path)
    raw = json.dumps(plan()).encode()
    raw += b" " * (262144 - len(raw))
    assert len(raw) == 262144
    path = root / core.PLAN_FILE
    path.write_bytes(raw)
    assert core.read_plan(root) == legacy.read_plan(root) == plan()
    path.write_bytes(raw + b" ")
    with pytest.raises(HostRefusal) as caught:
        core.read_plan(root)
    assert caught.value.reason == "too_large"
    assert path.read_bytes() == raw + b" "
    path.write_bytes(raw)
    assert core.read_plan(root) == plan()



def test_symlink_leaf_and_ancestor_refuse_without_reading(tmp_path):
    root = make_store(tmp_path)
    outside = root / "outside"
    outside.mkdir()
    write_plan(outside)
    link = root / core.PLAN_FILE
    symlink_or_skip(outside / core.PLAN_FILE, link)
    with pytest.raises(HostRefusal) as caught:
        core.read_plan(root)
    assert caught.value.reason == "unsafe_path"
    linked = root / "linked"
    symlink_or_skip(outside, linked, target_is_directory=True)
    with pytest.raises(HostRefusal) as caught:
        core.read_plan(linked)
    assert caught.value.reason == "unsafe_path"


def test_held_parent_survives_concurrent_ancestor_replacement(tmp_path, monkeypatch):
    root = make_store(tmp_path) / "base"
    root.mkdir()
    write_plan(root)
    replacement = tmp_path / "outside"
    replacement.mkdir()
    write_plan(replacement, dict(plan(), root=legacy.CLAUDE))
    held = tmp_path / "held"
    original = core.confined_file
    @contextmanager
    def swapped(base, parts):
        with original(base, parts) as handle:
            root.rename(held)
            symlink_or_skip(replacement, root, target_is_directory=True)
            yield handle
    monkeypatch.setattr(core, "confined_file", swapped)
    assert core.read_plan(root) == plan()


def test_unsupported_platform_refuses_even_when_plan_absent(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "descriptor_supported", lambda: False)
    with pytest.raises(HostRefusal) as caught:
        core.read_plan(tmp_path)
    assert caught.value.reason == "unsupported_platform"
    assert caught.value.code == 1 and caught.value.next_action
    assert list(tmp_path.iterdir()) == []


def test_parse_failure_releases_confined_context(tmp_path, monkeypatch):
    root = make_store(tmp_path)
    (root / core.PLAN_FILE).write_text("{")
    original = core.confined_file
    closed = []
    @contextmanager
    def tracked(base, parts):
        try:
            with original(base, parts) as handle:
                yield handle
        finally:
            closed.append(True)
    monkeypatch.setattr(core, "confined_file", tracked)
    with pytest.raises(HostRefusal):
        core.read_plan(root)
    assert closed == [True]
    write_plan(root)
    assert core.read_plan(root) == plan()
    assert closed == [True, True]


@pytest.mark.parametrize("delta", [
    {"hierarchy": "untrusted-marker/invalid"}, {"root": "untrusted-marker"},
    {"team": []}, {"stand_ins": {"alpha/root": "codex-cli"}},
    {"stand_ins": {"beta/front-door": "codex-cli"}}, {"config_sha256": "untrusted-marker"},
])
def test_invalid_plan_fields_refuse_then_valid_retry(delta):
    value = dict(plan(), **delta)
    with pytest.raises(ValueError):
        legacy.validate_plan(value)
    with pytest.raises(HostRefusal) as caught:
        core.validate_plan(value)
    assert caught.value.reason == "invalid_plan"
    assert "untrusted-marker" not in str(caught.value)
    assert core.validate_plan(plan()) == plan()


def test_relative_session_record_path_retains_pure_legacy_result():
    assert core.session_record_path("relative-base", "alpha/root", 1) == legacy.session_record_path(
        "relative-base", "alpha/root", 1)


def test_oversized_plan_never_reaches_json_parser(tmp_path, monkeypatch):
    root = make_store(tmp_path)
    path = root / core.PLAN_FILE
    path.write_bytes(b" " * (core.MAX_BYTES + 1))
    parsed = []
    def unexpected_parse(raw):
        parsed.append(True)
        raise AssertionError("oversized file reached parser")
    monkeypatch.setattr(core, "strict_json", unexpected_parse)
    with pytest.raises(HostRefusal) as caught:
        core.read_plan(root)
    assert caught.value.reason == "too_large"
    assert parsed == []


def test_read_failure_releases_context_and_retry_succeeds(tmp_path, monkeypatch):
    root = make_store(tmp_path)
    write_plan(root)
    original = core.confined_file
    closed = []
    class BrokenRead:
        def read_bytes(self, limit):
            raise OSError("untrusted-marker")
    @contextmanager
    def failing(base, parts):
        try:
            with original(base, parts):
                yield BrokenRead()
        finally:
            closed.append(True)
    monkeypatch.setattr(core, "confined_file", failing)
    with pytest.raises(HostRefusal) as caught:
        core.read_plan(root)
    assert caught.value.reason == "io"
    assert "untrusted-marker" not in str(caught.value)
    monkeypatch.setattr(core, "confined_file", original)
    assert closed == [True]
    assert core.read_plan(root) == plan()


def test_session_record_read_anchors_replaced_sessions_parent(tmp_path, monkeypatch):
    root = make_store(tmp_path)
    record = core.session_record("alpha/root", "root", legacy.CODEX, "exec", "session", 1,
                                 False, {"boundary": "reader"})
    path = core.session_record_path(root, "alpha/root", 1)
    path.parent.mkdir()
    path.write_text(json.dumps(record))
    original = core.confined_file
    @contextmanager
    def swapped(base, parts):
        with original(base, parts) as handle:
            path.parent.rename(root / "held")
            path.parent.mkdir()
            path.write_text(json.dumps(dict(record, session="foreign")))
            yield handle
    monkeypatch.setattr(core, "confined_file", swapped)
    assert core.session_recorded(path, record)


