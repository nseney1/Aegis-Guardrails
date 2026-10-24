"""The user-scope key ``insights.capture`` (v4.3 spec §7, R-evidence-b1).

``~/.aegis/config.json`` ``{"insights": {"capture": "off" | "counters" | "excerpts"}}`` can only
narrow what the host hook entry allows (``--excerpts`` or ``--no-excerpts``): the passive hook
runs with the lower of the two, ``off`` touches no state at all, and an unset, invalid or
unreadable value, a repository key or a user file inside the workspace leaves the entry's mode.
Every test uses a fake HOME, installs the entry with the real installer and never runs a host CLI.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess

import pytest

from aegis_cli.hooks import registrar
from aegis_cli.hooks.insights import run_insight_hook
from aegis_core.config import MAX_CONFIG_BYTES, UserConfig, parse_capture_mode
from aegis_core.insights import effective_capture, host_capture_status, insights_path, read_insight_rows
from aegis_core.workspace.layout import UserLayout
from aegis_mcp.tools import execute_tool

CUE = "No, stop editing the build file again."
RULE = ("---\nid: trap-one\ntype: trap\nenforcement: advisory\nhypothesis: One.\n"
        "target_paths:\n  - src/*.py\n---\n# trap-one\n\nNever do the one thing.\n")


def _workspace(root: Path) -> Path:
    (root / ".aegis" / "rules" / "traps").mkdir(parents=True)
    (root / ".aegis" / "rules" / "traps" / "trap-one.md").write_bytes(RULE.encode("utf-8"))
    subprocess.run(["git", "init", "-q", str(root)], check=True, capture_output=True)
    return root


@pytest.fixture
def env(tmp_path, monkeypatch):
    for name in ("CLAUDE_CONFIG_DIR", "CODEX_HOME", "CLAUDE_PROJECT_DIR", "AEGIS_WORKSPACE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    ws = _workspace(tmp_path / "ws")
    return _with_home(monkeypatch, tmp_path / "home", ws)


def _with_home(monkeypatch, home: Path, ws: Path) -> argparse.Namespace:
    home.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    return argparse.Namespace(home=home, ws=ws)


def _user_config(env, body) -> None:
    (env.home / ".aegis").mkdir(parents=True, exist_ok=True)
    data = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")
    (env.home / ".aegis" / "config.json").write_bytes(data)


def _install(env, excerpts: bool) -> list:
    """The entry the installer writes; the argv the host passes is its tail from --host. The
    installer creates link.key: it is removed so a test sees whether the hook makes it again."""
    registrar.install_insight_hook("claude-code", excerpts, home=env.home, environ={})
    (env.home / ".aegis" / "link.key").unlink()
    settings = json.loads((env.home / ".claude" / "settings.json").read_text(encoding="utf-8"))
    args = settings["hooks"]["UserPromptSubmit"][-1]["hooks"][0]["args"]
    return args[args.index("--host"):]


def _hook(env, capsys, argv: list, prompt: str = CUE) -> list:
    payload = {"prompt": prompt, "session_id": "s-capture", "cwd": str(env.ws)}
    assert run_insight_hook(argv, stdin=json.dumps(payload), home=env.home) == 0
    out = capsys.readouterr()
    assert (out.out, out.err) == ("", "")
    return read_insight_rows(env.ws, home=env.home)


def _capture(env) -> tuple:
    status = host_capture_status("claude-code", home=env.home)
    return status["capture"], status["capture_source"]


def test_off_writes_nothing_and_touches_no_state(env, capsys):
    """Given capture 'off' and an --excerpts entry, When a cue prompt arrives, Then the hook exits 0
    silently, writes no insight file and no link.key, and doctor's dict reports off from the key."""
    _user_config(env, {"v": 1, "insights": {"capture": "off"}})
    argv = _install(env, excerpts=True)
    assert _hook(env, capsys, argv) == []
    assert not insights_path(env.ws, home=env.home).exists()
    assert not (env.home / ".aegis" / "link.key").exists()
    status = host_capture_status("claude-code", home=env.home)
    assert (status["status"], status["excerpts"]) == ("enabled_excerpts", True)  # the entry, as installed
    assert _capture(env) == ("off", "insights.capture")


def _tree(root: Path) -> dict:
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}


@pytest.mark.parametrize("where", ["cwd", "project", "parent"])
def test_off_holds_when_the_session_directory_is_home_or_above_it(env, capsys, monkeypatch, where):
    """Given capture 'off' and an --excerpts entry, When the session directory is HOME (the payload
    cwd or CLAUDE_PROJECT_DIR) or a parent of HOME, Then the hook touches nothing, as doctor reports:
    no governed workspace holds ~/.aegis/config.json, though that directory does."""
    _user_config(env, {"v": 1, "insights": {"capture": "off"}})
    argv = _install(env, excerpts=True)
    cwd = {"cwd": env.home, "project": env.ws, "parent": env.home.parent}[where]
    if where == "project":
        monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(env.home))
    before = _tree(env.home.parent)
    payload = {"prompt": CUE, "session_id": "s-capture", "cwd": str(cwd)}
    assert run_insight_hook(argv, stdin=json.dumps(payload), home=env.home) == 0
    assert capsys.readouterr().err == ""
    assert _tree(env.home.parent) == before
    assert not (env.home / ".aegis" / "link.key").exists()
    assert _capture(env) == ("off", "insights.capture")


def test_counters_strips_excerpts_from_an_excerpts_entry(env, capsys):
    _user_config(env, {"v": 1, "insights": {"capture": "counters"}})
    rows = _hook(env, capsys, _install(env, excerpts=True))
    assert "heartbeat" in [r["event"] for r in rows]
    assert "insight" not in [r["event"] for r in rows] and "build file" not in json.dumps(rows)
    assert _capture(env) == ("counters", "insights.capture")


def test_the_key_never_widens_a_no_excerpts_entry(env, capsys):
    _user_config(env, {"v": 1, "insights": {"capture": "excerpts"}})
    rows = _hook(env, capsys, _install(env, excerpts=False))
    assert "heartbeat" in [r["event"] for r in rows] and "build file" not in json.dumps(rows)
    assert _capture(env) == ("counters", "host entry")


def test_unset_leaves_the_entry_mode(env, capsys):
    rows = _hook(env, capsys, _install(env, excerpts=True))
    assert [r["text"] for r in rows if r["event"] == "insight"] == [CUE]
    assert _capture(env) == ("excerpts", "host entry")


def test_padding_and_case_are_accepted(env, capsys):
    _user_config(env, {"v": 1, "insights": {"capture": " Off "}})
    assert _hook(env, capsys, _install(env, excerpts=True)) == []
    assert _capture(env) == ("off", "insights.capture")


@pytest.mark.parametrize("value", ["all", 7, ""])
def test_an_invalid_value_is_warned_about_and_changes_nothing(env, capsys, value):
    _user_config(env, {"v": 1, "insights": {"capture": value}})
    rows = _hook(env, capsys, _install(env, excerpts=True))
    assert [r["text"] for r in rows if r["event"] == "insight"] == [CUE]
    assert _capture(env) == ("excerpts", "host entry")
    assert UserConfig.load(env.ws, user=UserLayout(env.home)).warnings == (
        "ignored 'insights.capture' in ~/.aegis/config.json: expected off, counters or excerpts",)


def test_null_counts_as_unset_and_warns_nothing(env, capsys):
    _user_config(env, {"v": 1, "insights": {"capture": None}})
    rows = _hook(env, capsys, _install(env, excerpts=True))
    assert [r["event"] for r in rows if r["event"] == "insight"] == ["insight"]
    assert UserConfig.load(env.ws, user=UserLayout(env.home)).warnings == ()


@pytest.mark.parametrize("section", ["off", ["off"], 0])
def test_a_section_that_is_not_an_object_is_warned_about(section):
    config = UserConfig.parse({"v": 1, "insights": section})
    assert config.insights_capture is None
    assert config.warnings == ("ignored 'insights' in ~/.aegis/config.json: it must be an object",)


def test_a_repository_key_is_never_read_for_capture(env, capsys):
    (env.ws / ".aegis" / "config.json").write_bytes(json.dumps({"v": 1, "insights": {"capture": "off"}}).encode())
    rows = _hook(env, capsys, _install(env, excerpts=True))
    assert [r["event"] for r in rows if r["event"] == "insight"] == ["insight"]


def test_a_user_config_inside_the_workspace_is_ignored(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for name in ("CLAUDE_CONFIG_DIR", "CODEX_HOME", "CLAUDE_PROJECT_DIR", "AEGIS_WORKSPACE"):
        monkeypatch.delenv(name, raising=False)
    ws = _workspace(tmp_path / "ws")
    env = _with_home(monkeypatch, ws / "home", ws)
    _user_config(env, {"v": 1, "insights": {"capture": "off"}})
    rows = _hook(env, capsys, _install(env, excerpts=True))
    assert [r["event"] for r in rows if r["event"] == "insight"] == ["insight"]


# The size and version bodies would turn capture off: the test fails if the reader took them.
@pytest.mark.parametrize("body", [
    b"{not json",
    b'{"v": 1, "insights": {"capture": "off"}, "pad": "' + b" " * MAX_CONFIG_BYTES + b'"}',
    b'{"v": 9, "insights": {"capture": "off"}}',
], ids=["json", "size", "version"])
def test_an_unusable_user_config_leaves_the_entry_mode(env, capsys, body):
    _user_config(env, body)
    rows = _hook(env, capsys, _install(env, excerpts=True))
    assert [r["event"] for r in rows if r["event"] == "insight"] == ["insight"]
    assert _capture(env) == ("excerpts", "host entry")


def test_an_unreadable_user_config_leaves_the_entry_mode(env, capsys):
    (env.home / ".aegis" / "config.json").mkdir(parents=True)  # not a regular file
    rows = _hook(env, capsys, _install(env, excerpts=True))
    assert [r["event"] for r in rows if r["event"] == "insight"] == ["insight"]


@pytest.mark.parametrize("entry,configured,expected", [
    (True, None, ("excerpts", "host entry")),
    (True, "counters", ("counters", "insights.capture")),
    (True, "off", ("off", "insights.capture")),
    (False, "excerpts", ("counters", "host entry")),
    (False, "counters", ("counters", "host entry")),
    (False, "off", ("off", "insights.capture")),
])
def test_the_mode_is_the_lower_of_the_entry_and_the_key(env, entry, configured, expected):
    if configured:
        _user_config(env, {"v": 1, "insights": {"capture": configured}})
    assert effective_capture(entry, env.ws, home=env.home) == expected


def test_the_key_is_known_to_the_user_config():
    config = UserConfig.parse({"v": 1, "insights": {"capture": "off"}})
    assert (config.insights_capture, config.warnings) == ("off", ())


def test_parse_capture_mode_accepts_the_three_values_only():
    assert [parse_capture_mode(v) for v in ("off", " Counters", "EXCERPTS\n")] == ["off", "counters", "excerpts"]
    assert [parse_capture_mode(v) for v in ("all", "", 7, None, True, ["off"])] == [None] * 6


def test_explicit_capture_is_not_governed_by_the_key(env):
    """AG-9: the MCP capture tool is an explicit action; capture 'off' governs the passive hook only."""
    _user_config(env, {"v": 1, "insights": {"capture": "off"}})
    result = execute_tool("aegis_capture_insight", {"workspace": str(env.ws), "quote": "Always pin the versions",
                                                    "paths": ["src/a.py"], "_host": "claude-code", "_session": "s1"})
    assert result["status"] == "OK", result
    assert [r["text"] for r in read_insight_rows(env.ws, home=env.home)] == ["Always pin the versions"]
