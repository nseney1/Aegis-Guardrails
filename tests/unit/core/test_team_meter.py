"""Meter parity, confined transcript reads, typed failures and valid retries."""
from concurrent.futures import ThreadPoolExecutor
import errno
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

from aegis_core import team_meter as meter
from tests.conftest import symlink_or_skip

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tools"))
from tools import hierarchy_meter as legacy  # noqa: E402

SESSION = "01a19a29-d635-7411-8529-9efedafc0881"


def supported():
    if not meter.descriptor_supported():
        pytest.skip("meter requires descriptor-relative no-follow opens")


def event(seconds, kind):
    return {"timestamp": "2026-11-02T00:%02d:%02d.000Z" % divmod(seconds, 60),
            "type": "event_msg", "payload": {"type": kind}}


def transcript(tmp_path, rows=None):
    supported()
    path = tmp_path / "sessions" / ("rollout-" + SESSION + ".jsonl")
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = rows if rows is not None else [event(0, "task_started"), event(90, "task_complete")]
    path.write_text("".join((row if isinstance(row, str) else json.dumps(row)) + "\n" for row in rows),
                    encoding="utf-8")
    return path


def refused(caught, reason):
    assert caught.value.as_dict() == {"status": "refused", "reason": reason, "code": 1,
                                     "next_action": caught.value.next_action}
    assert caught.value.next_action


@pytest.mark.parametrize("rows", [
    [event(0, "task_started"), event(90, "task_complete")],
    [event(0, "task_started"), event(10, "token_count")],
    [event(0, "task_started"), event(10, "task_started"), event(20, "turn_aborted")],
    ["bad", " ", {"timestamp": "bad"}, {"type": "other"}, event(0, "task_started")],
])
def test_codex_parity(tmp_path, rows):
    path = transcript(tmp_path, rows)
    assert meter.measure("codex-cli", SESSION, path, home=tmp_path) == legacy.measure("codex-cli", SESSION, path)
    assert meter.find_transcript("codex-cli", SESSION, home=tmp_path) == path


@pytest.mark.parametrize("limit", [90, 100, 5400])
def test_threshold_parity_and_parallel_reads(tmp_path, limit):
    path = transcript(tmp_path)
    expected = legacy.measure("codex-cli", SESSION, path, limit)
    with ThreadPoolExecutor(max_workers=3) as pool:
        answers = list(pool.map(lambda _: meter.measure("codex-cli", SESSION, path, limit, home=tmp_path), range(6)))
    assert answers == [expected] * 6


def test_claude_parity(tmp_path):
    rows = [{"timestamp": event(0, "unused")["timestamp"], "type": "user", "message": {"content": "prompt"}},
            {"timestamp": event(20, "unused")["timestamp"], "type": "assistant"},
            {"timestamp": event(50, "unused")["timestamp"], "type": "queue-operation"}]
    path = transcript(tmp_path, rows)
    assert meter.measure("claude-code", SESSION, path, home=tmp_path) == legacy.measure("claude-code", SESSION, path)


@pytest.mark.parametrize("host,session,limit,reason", [
    ([], SESSION, 3600, "unknown_host"), ("unknown", SESSION, 3600, "unknown_host"),
    ("codex-cli", "../x", 3600, "invalid_session"), ("codex-cli", [], 3600, "invalid_session"),
    ("codex-cli", SESSION, True, "invalid_limit"), ("codex-cli", SESSION, 86401, "invalid_limit"),
])
def test_invalid_inputs_are_fixed(host, session, limit, reason):
    with pytest.raises(meter.MeterRefusal) as caught:
        meter.measure(host, session, limit=limit)
    refused(caught, reason)


def test_invalid_discovery_preserves_none():
    assert meter.find_transcript([], SESSION) is None
    assert meter.find_transcript("codex-cli", "../x") is None


def test_outside_home_refuses_and_valid_retry_succeeds(tmp_path):
    path = transcript(tmp_path)
    with pytest.raises(meter.MeterRefusal) as caught:
        meter.measure("codex-cli", SESSION, path, home=tmp_path / "different-home")
    refused(caught, "unsafe_path")
    assert meter.measure("codex-cli", SESSION, path, home=tmp_path)["active_seconds"] == 90


def test_missing_transcript_parity_and_missing_override(tmp_path, monkeypatch):
    supported()
    monkeypatch.setattr(legacy, "os", SimpleNamespace(**{**vars(os), "environ": {"CODEX_HOME": str(tmp_path)}}))
    assert meter.measure("codex-cli", SESSION, home=tmp_path) == legacy.measure("codex-cli", SESSION)
    with pytest.raises(meter.MeterRefusal) as caught:
        meter.measure("codex-cli", SESSION, tmp_path / "missing", home=tmp_path)
    refused(caught, "transcript_unavailable")


def test_unsupported_platform_is_its_own_refusal(tmp_path, monkeypatch):
    monkeypatch.setattr(meter, "descriptor_supported", lambda: False)
    with pytest.raises(meter.MeterRefusal) as caught:
        meter.measure("codex-cli", SESSION, tmp_path / "sessions" / "one.jsonl", home=tmp_path)
    refused(caught, "unsupported_platform")


@pytest.mark.parametrize("component", ["file", "ancestor"])
def test_symlinks_refuse_without_reading_outside(tmp_path, component):
    path = transcript(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    if component == "file":
        path.unlink()
        symlink_or_skip(outside / "unread", path)
    else:
        path.parent.rename(tmp_path / "old-sessions")
        symlink_or_skip(outside, path.parent, target_is_directory=True)
    with pytest.raises(meter.MeterRefusal) as caught:
        meter.measure("codex-cli", SESSION, path, home=tmp_path)
    refused(caught, "unsafe_path")


def test_rename_after_open_reads_only_held_directory(tmp_path, monkeypatch):
    path = transcript(tmp_path)
    real = os.open
    moved = []
    def opening(name, flags, *args, **kwargs):
        fd = real(name, flags, *args, **kwargs)
        if name == "sessions" and not moved:
            moved.append(True)
            path.parent.rename(tmp_path / "retained")
            path.parent.mkdir()
            path.write_text("not the retained transcript\n", encoding="utf-8")
        return fd
    monkeypatch.setattr(meter, "os", SimpleNamespace(**{**vars(os), "open": opening}))
    assert meter.measure("codex-cli", SESSION, path, home=tmp_path)["active_seconds"] == 90
    assert moved


def test_fdopen_failure_closes_all_owned_descriptors(tmp_path, monkeypatch):
    path = transcript(tmp_path)
    opened = []
    real = os.open
    def opening(*args, **kwargs):
        fd = real(*args, **kwargs)
        opened.append(fd)
        return fd
    def fail(*args, **kwargs):
        raise OSError(errno.EIO, "untrusted diagnostic")
    monkeypatch.setattr(meter, "os", SimpleNamespace(**{**vars(os), "open": opening, "fdopen": fail}))
    with pytest.raises(meter.MeterRefusal) as caught:
        meter.measure("codex-cli", SESSION, path, home=tmp_path)
    refused(caught, "transcript_unavailable")
    assert "untrusted diagnostic" not in str(caught.value)
    for fd in set(opened):
        with pytest.raises(OSError) as closed:
            os.fstat(fd)
        assert closed.value.errno == errno.EBADF
    monkeypatch.setattr(meter, "os", os)
    assert meter.measure("codex-cli", SESSION, path, home=tmp_path)["active_seconds"] == 90


@pytest.mark.parametrize("kind", ["line", "file", "records", "depth"])
def test_limits_refuse_before_parsing_and_retry(tmp_path, monkeypatch, kind):
    path = transcript(tmp_path)
    file_limit, record_limit = meter.MAX_TRANSCRIPT_BYTES, meter.MAX_RECORDS
    if kind == "line":
        path.write_bytes(b"x" * (meter.MAX_LINE_BYTES + 1))
    elif kind == "file":
        monkeypatch.setattr(meter, "MAX_TRANSCRIPT_BYTES", 2)
    elif kind == "records":
        monkeypatch.setattr(meter, "MAX_RECORDS", 1)
    else:
        path.write_text("[" * 200 + "0" + "]" * 200 + "\n", encoding="utf-8")
    with pytest.raises(meter.MeterRefusal) as caught:
        meter.measure("codex-cli", SESSION, path, home=tmp_path)
    refused(caught, "transcript_limit")
    monkeypatch.setattr(meter, "MAX_TRANSCRIPT_BYTES", file_limit)
    monkeypatch.setattr(meter, "MAX_RECORDS", record_limit)
    path.write_text(json.dumps(event(0, "task_started")) + "\n" + json.dumps(event(90, "task_complete")) + "\n",
                    encoding="utf-8")
    assert meter.measure("codex-cli", SESSION, path, home=tmp_path)["active_seconds"] == 90


def test_universal_newline_parity(tmp_path):
    path = transcript(tmp_path)
    path.write_bytes(path.read_bytes().replace(b"\n", b"\r"))
    assert meter.measure("codex-cli", SESSION, path, home=tmp_path) == legacy.measure("codex-cli", SESSION, path)


def test_newest_archived_transcript_is_selected(tmp_path):
    path = transcript(tmp_path)
    archived = tmp_path / "archived_sessions" / path.name
    archived.parent.mkdir()
    archived.write_bytes(path.read_bytes())
    os.utime(path, (1700000000, 1700000000))
    os.utime(archived, (1700000060, 1700000060))
    assert meter.find_transcript("codex-cli", SESSION, home=tmp_path) == archived


def test_unavailable_default_home_refuses_and_retries(tmp_path, monkeypatch):
    path = transcript(tmp_path)
    def unavailable():
        raise RuntimeError("untrusted home diagnostic")
    monkeypatch.setattr(meter, "Path", SimpleNamespace(home=unavailable))
    monkeypatch.setattr(meter, "os", SimpleNamespace(**{**vars(os), "environ": {}}))
    with pytest.raises(meter.MeterRefusal) as caught:
        meter.measure("codex-cli", SESSION, path)
    refused(caught, "transcript_unavailable")
    monkeypatch.setattr(meter, "os", os)
    assert meter.measure("codex-cli", SESSION, path, home=tmp_path)["active_seconds"] == 90


@pytest.mark.parametrize("kind", [[], {}], ids=["list", "mapping"])
def test_unhashable_event_kind_refusal_parity_and_retry(tmp_path, kind):
    path = transcript(tmp_path, [event(0, "task_started"), event(90, kind)])
    with pytest.raises(TypeError):
        legacy.measure("codex-cli", SESSION, path)
    with pytest.raises(meter.MeterRefusal) as caught:
        meter.measure("codex-cli", SESSION, path, home=tmp_path)
    refused(caught, "invalid_record")
    path.write_text(json.dumps(event(0, "task_started")) + "\n" + json.dumps(event(90, "task_complete")) + "\n",
                    encoding="utf-8")
    assert meter.measure("codex-cli", SESSION, path, home=tmp_path)["active_seconds"] == 90


def test_explicit_home_is_confined_without_changing_environment(tmp_path):
    supported()
    before = dict(os.environ)
    path = tmp_path / "sessions" / ("rollout-" + SESSION + ".jsonl")
    path.parent.mkdir()
    path.write_text(json.dumps(event(0, "task_started")) + "\n" + json.dumps(event(90, "task_complete")) + "\n",
                    encoding="utf-8")
    assert meter.find_transcript("codex-cli", SESSION, home=tmp_path) == path
    assert meter.measure("codex-cli", SESSION, home=tmp_path)["active_seconds"] == 90
    with pytest.raises(meter.MeterRefusal) as caught:
        meter.measure("codex-cli", SESSION, path, home=tmp_path / "different-home")
    refused(caught, "unsafe_path")
    assert meter.measure("codex-cli", SESSION, path, home=tmp_path)["active_seconds"] == 90
    unchanged = dict(os.environ) == before
    assert unchanged, "The meter changed the process environment."


def test_default_home_resolves_at_each_call(tmp_path, monkeypatch):
    path = transcript(tmp_path)
    before = dict(os.environ)
    monkeypatch.setattr(meter, "os", SimpleNamespace(**{**vars(os), "environ": {"CODEX_HOME": str(tmp_path)}}))
    assert meter.find_transcript("codex-cli", SESSION) == path
    assert meter.measure("codex-cli", SESSION, path)["active_seconds"] == 90
    changed_home = {"CODEX_HOME": str(tmp_path / "missing")}
    monkeypatch.setattr(meter, "os", SimpleNamespace(**{**vars(os), "environ": changed_home}))
    assert meter.find_transcript("codex-cli", SESSION) is None
    assert meter.measure("codex-cli", SESSION, path, home=tmp_path)["active_seconds"] == 90
    unchanged = dict(os.environ) == before
    assert unchanged, "The meter changed the process environment."


@pytest.mark.parametrize("empty", [False, True])
def test_default_home_fallback_is_retained(tmp_path, monkeypatch, empty):
    home = tmp_path / meter.hosts.entry("codex-cli")["home"]["owner_folder"]
    path = transcript(home)
    environment = {"CODEX_HOME": ""} if empty else {}
    monkeypatch.setattr(meter, "os", SimpleNamespace(**{**vars(os), "environ": environment}))
    monkeypatch.setattr(meter, "Path", SimpleNamespace(home=lambda: tmp_path))
    assert meter.find_transcript("codex-cli", SESSION) == path
    assert meter.measure("codex-cli", SESSION, path)["active_seconds"] == 90
