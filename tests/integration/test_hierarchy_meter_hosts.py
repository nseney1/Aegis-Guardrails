"""The meter finds host transcripts while preserving its existing lookup contract."""
import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

from tests.integration.test_hierarchy_mailbox import ROOT


sys.path.insert(0, str(ROOT / "tools"))
import hierarchy_meter  # noqa: E402


SESSION = "real-session"
HOSTS = (("claude-code", "CLAUDE_CONFIG_DIR", ".claude"),
         ("codex-cli", "CODEX_HOME", ".codex"), ("codex", "CODEX_HOME", ".codex"))


def touch(path, mtime=1700000000):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("", encoding="utf-8")
    os.utime(path, (mtime, mtime))
    return path


def test_host_sets_keep_the_existing_members():
    assert isinstance(hierarchy_meter.CLAUDE_HOSTS, set)
    assert isinstance(hierarchy_meter.CODEX_HOSTS, set)
    assert hierarchy_meter.CLAUDE_HOSTS == {"claude-code"}
    assert hierarchy_meter.CODEX_HOSTS == {"codex", "codex-cli"}


@pytest.mark.parametrize("host,variable,folder", HOSTS)
@pytest.mark.parametrize("home_value", ["set", "unset", "empty"])
def test_home_lookup_uses_the_registry_declaration(tmp_path, monkeypatch, host, variable, folder, home_value):
    registry = hierarchy_meter.hierarchy_hosts

    def entry(kind):
        spec = registry.entry(kind)
        spec["home"].update(variable="AEGIS_TEST_METER_HOME", owner_folder=".meter-host")
        return spec

    class MeterPath(type(tmp_path)):
        @classmethod
        def home(cls):
            return tmp_path

    monkeypatch.setattr(hierarchy_meter, "hierarchy_hosts", SimpleNamespace(**{**vars(registry), "entry": entry}))
    monkeypatch.setattr(hierarchy_meter, "Path", MeterPath)
    monkeypatch.setenv(variable, str(tmp_path / "old-home"))
    if home_value == "set":
        home = tmp_path / "configured-home"
        monkeypatch.setenv("AEGIS_TEST_METER_HOME", str(home))
    else:
        home = tmp_path / ".meter-host"
        if home_value == "empty":
            monkeypatch.setenv("AEGIS_TEST_METER_HOME", "")
        else:
            monkeypatch.delenv("AEGIS_TEST_METER_HOME", raising=False)
    relative = (Path("projects") / "slug" / (SESSION + ".jsonl") if host == "claude-code"
                else Path("sessions") / ("rollout-" + SESSION + ".jsonl"))
    transcript = touch(home / relative)
    touch(tmp_path / "old-home" / relative)
    touch(tmp_path / folder / relative)
    assert hierarchy_meter.find_transcript(host, SESSION) == transcript


@pytest.mark.parametrize("host", ["codex-cli", "codex"])
def test_codex_rollout_found_only_in_archived_sessions(tmp_path, monkeypatch, host):
    monkeypatch.setenv("CODEX_HOME", str(tmp_path))
    archived = touch(tmp_path / "archived_sessions" / ("rollout-2026-11-07-" + SESSION + ".jsonl"))
    assert hierarchy_meter.find_transcript(host, SESSION) == archived


@pytest.mark.parametrize("host", ["codex-cli", "codex"])
@pytest.mark.parametrize("newest_folder", ["sessions", "archived_sessions"])
def test_newest_mtime_wins_across_live_and_archived_rollouts(tmp_path, monkeypatch, host, newest_folder):
    monkeypatch.setenv("CODEX_HOME", str(tmp_path))
    paths = {folder: touch(tmp_path / folder / "2026" / "11" / "07" / ("rollout-" + SESSION + ".jsonl"),
                          1700000060 if folder == newest_folder else 1700000000)
             for folder in ("sessions", "archived_sessions")}
    assert hierarchy_meter.find_transcript(host, SESSION) == paths[newest_folder]


def test_claude_transcript_found_under_project_slug(tmp_path, monkeypatch):
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path))
    transcript = touch(tmp_path / "projects" / "-work-lane" / (SESSION + ".jsonl"))
    touch(tmp_path / "projects" / "-work-lane" / "other-session.jsonl", 1700000060)
    assert hierarchy_meter.find_transcript("claude-code", SESSION) == transcript


@pytest.mark.parametrize("host,variable,folder", HOSTS)
def test_missing_home_returns_none(tmp_path, monkeypatch, host, variable, folder):
    monkeypatch.setenv(variable, str(tmp_path / "missing"))
    assert hierarchy_meter.find_transcript(host, SESSION) is None


@pytest.mark.parametrize("host,variable,folder", HOSTS)
@pytest.mark.parametrize("empty", [False, True])
def test_unset_or_empty_home_uses_the_existing_default(tmp_path, monkeypatch, host, variable, folder, empty):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    if empty:
        monkeypatch.setenv(variable, "")
    else:
        monkeypatch.delenv(variable, raising=False)
    home = tmp_path / folder
    relative = (Path("projects") / "slug" / (SESSION + ".jsonl") if host == "claude-code"
                else Path("sessions") / ("rollout-" + SESSION + ".jsonl"))
    transcript = touch(home / relative)
    assert hierarchy_meter.find_transcript(host, SESSION) == transcript


@pytest.mark.parametrize("host,variable,folder", HOSTS)
@pytest.mark.parametrize("session", ["", "*", "a*b", "../x", "[ab]"])
def test_invalid_sessions_do_not_match_existing_transcripts(tmp_path, monkeypatch, host, variable, folder, session):
    monkeypatch.setenv(variable, str(tmp_path))
    for name in ("", "a", "ab", "x", SESSION):
        relative = (Path("projects") / "slug" / (name + ".jsonl") if host == "claude-code"
                    else Path("sessions") / ("rollout-" + name + ".jsonl"))
        touch(tmp_path / relative)
    touch(tmp_path / "projects" / "x.jsonl")
    assert hierarchy_meter.find_transcript(host, session) is None
    with pytest.raises(ValueError, match="^invalid session$"):
        hierarchy_meter.measure(host, session)


@pytest.mark.parametrize("host", ["unknown", "", None, []])
def test_unknown_hosts_do_not_match_existing_transcripts(tmp_path, monkeypatch, host):
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path))
    monkeypatch.setenv("CODEX_HOME", str(tmp_path))
    touch(tmp_path / "projects" / "slug" / (SESSION + ".jsonl"))
    touch(tmp_path / "sessions" / ("rollout-" + SESSION + ".jsonl"))
    assert hierarchy_meter.find_transcript(host, SESSION) is None


@pytest.mark.parametrize("host,variable,folder", HOSTS)
@pytest.mark.parametrize("session", [None, 7])
def test_non_string_sessions_return_none(tmp_path, monkeypatch, host, variable, folder, session):
    monkeypatch.setenv(variable, str(tmp_path))
    touch(tmp_path / "projects" / "slug" / (SESSION + ".jsonl"))
    touch(tmp_path / "sessions" / ("rollout-" + SESSION + ".jsonl"))
    assert hierarchy_meter.find_transcript(host, session) is None
