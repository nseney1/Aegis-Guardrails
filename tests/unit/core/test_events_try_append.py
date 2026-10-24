"""A best-effort event keeps the decision and each caller's warning words."""
from types import SimpleNamespace

import pytest

from aegis_cli import skills_sync, verify
from aegis_core import events, lane_gate, partition, team


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    for key in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(key, str(home))
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(home / "gitconfig"))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for key in ("CLAUDE_CONFIG_DIR", "CODEX_HOME", "XDG_CONFIG_HOME"):
        monkeypatch.delenv(key, raising=False)


def _raise(error):
    def broken(*args, **kwargs):
        raise error
    return broken


def test_existing_verify_and_skills_warning_words(tmp_path, monkeypatch):
    monkeypatch.setattr(events, "append", _raise(OSError("disk full")))
    assert verify._event_warning(str(tmp_path), "baseline_check", "ok", {}) == ["event not recorded: disk full"]
    result = skills_sync.SyncResult(["claude-code"], [], [], [], False, False)
    skills_sync._record(tmp_path, result, "sync")
    assert result.warnings == ["the skills_sync event could not be recorded (OSError: disk full)"]


def test_try_append_returns_storage_failure(tmp_path, monkeypatch):
    error = OSError(28, "disk full")
    monkeypatch.setattr(events, "append_jsonl", _raise(error))
    assert events.try_append(tmp_path, "package", "ok", {}) is error


def test_try_append_reports_invalid_inputs_and_success(tmp_path):
    assert isinstance(events.try_append(tmp_path, "bad-kind", "ok", {}), ValueError)
    assert isinstance(events.try_append(tmp_path, "package", "ok", []), ValueError)
    assert events.try_append(tmp_path, "package", "ok", {"files": 7}) is None
    row, = events.read(tmp_path).rows
    assert row["event"] == "package" and row["detail"] == {"files": 7}


@pytest.mark.parametrize("error", [KeyboardInterrupt(), SystemExit(9)])
def test_process_control_is_not_a_metric_warning(tmp_path, monkeypatch, error):
    monkeypatch.setattr(events, "append", _raise(error))
    with pytest.raises(type(error)):
        events.try_append(tmp_path, "package", "ok", {})
    from aegis_cli.hooks import pretool
    decision = SimpleNamespace(message="", event="guard_match", root=tmp_path, result="block", detail={}, code=2)
    monkeypatch.setattr(pretool, "_decide", lambda *args: decision)
    assert pretool.run_pre_tool("claude-code", b"{}", {}) == 2


def test_unexpected_event_failure_is_a_warning_at_all_narrow_sites(tmp_path, monkeypatch):
    monkeypatch.setattr(events, "append", _raise(RuntimeError("boom")))
    assert team._record(tmp_path, "lease_claimed", "ok", {}) == ("event not recorded: boom",)
    report = SimpleNamespace(passed=True, event_detail=lambda: {})
    assert lane_gate._record(tmp_path, report) == ("event not recorded: boom",)
    assert verify._event_warning(str(tmp_path), "baseline_check", "ok", {}) == ["event not recorded: boom"]
    result = partition.check(tmp_path, {"A": ("src/**",), "B": ("test/**",)})
    assert result.warnings == ("event not recorded: boom",)
