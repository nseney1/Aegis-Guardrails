"""Unit tests for MCP aegis_capture_insight tool."""
from __future__ import annotations

from pathlib import Path
import subprocess
import sys

import pytest

import aegis_core.insights as insights_mod
from aegis_core.insights import read_insight_rows, record_hook_prompt, review_insights
import aegis_mcp.server as server
from aegis_mcp.registry import TOOL_DEFINITIONS
from aegis_mcp.tools import execute_tool, is_known_tool


def _make_workspace(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    subprocess.run(["git", "-C", str(path), "config", "user.email", "mcp@example.com"], check=True)
    subprocess.run(["git", "-C", str(path), "config", "user.name", "MCP Test"], check=True)
    (path / ".aegis" / "rules" / "traps").mkdir(parents=True, exist_ok=True)
    (path / ".aegis" / "config.json").write_text('{"v": 1}\n', encoding="utf-8")
    (path / ".aegis" / ".gitignore").write_text("state/\n", encoding="utf-8")
    (path / "src").mkdir(exist_ok=True)
    (path / "src" / "service.py").write_text("y = 1\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(path), "add", "."], check=True)
    subprocess.run(["git", "-C", str(path), "commit", "-q", "-m", "init"], check=True)
    return path


def test_aegis_capture_insight_schema_and_annotations():
    assert is_known_tool("aegis_capture_insight")
    tool = next(t for t in TOOL_DEFINITIONS if t["name"] == "aegis_capture_insight")
    assert tool["annotations"] == {"readOnlyHint": False, "title": "Capture Insight"}
    schema = tool["inputSchema"]
    assert schema["required"] == ["quote"]
    assert set(schema["properties"]) == {"quote", "paths"}
    assert schema["additionalProperties"] is False


def test_aegis_capture_insight_records_suggestion_and_is_corroborated_never_upgraded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    ws = _make_workspace(tmp_path / "ws")

    # 1. Unconfirmed agent call -> level == 'suggestion'
    fake_tok = "".join(["sk_live_", "1234567890abcdefghijklmn"])
    res = execute_tool(
        "aegis_capture_insight",
        {
            "workspace": str(ws),
            "_host": "claude-code",
            "_session": "mcp-sess-1",
            "quote": f"Do not use token {fake_tok} in src/service.py",
            "paths": ["src/service.py"],
        },
    )
    assert res["status"] == "OK"
    assert res["level"] == "suggestion"
    assert "".join(["sk_", "live_"]) not in res["text"]
    assert res["paths"] == ["src/service.py"]
    assert res["psrc"] == "explicit"

    # An unconfirmed suggestion is never a counted insight
    rev = review_insights(ws, home=home)
    assert rev["insights"] == [] and rev["suppressed"] == []
    assert len(rev["suggestions"]) == 1

    # 2. The host's hook records a prompt containing the quote; the server's own session id
    # differs. The capture is corroborated (same host, inside the join window) and stays a
    # suggestion: only the hook row counts.
    hook = record_hook_prompt(
        "claude-code",
        {
            "prompt": "No, stop using raw os.system calls in src/service.py!",
            "session_id": "host-session-2",
            "cwd": str(ws),
        },
        workspace=ws, home=home,
    )
    res_corroborated = execute_tool(
        "aegis_capture_insight",
        {
            "workspace": str(ws),
            "_host": "claude-code",
            "_session": "server-uuid-2",
            "quote": "stop using raw os.system calls in src/service.py",
            "paths": ["src/service.py"],
        },
    )
    assert res_corroborated["status"] == "OK"
    assert res_corroborated["level"] == "suggestion"
    stored, = [r for r in read_insight_rows(ws, home=home) if r.get("id") == res_corroborated["id"]]
    assert stored["corroborated_by"] == hook["id"] and "confirmed_by" not in stored
    rev = review_insights(ws, home=home)
    assert [(e["id"], e["corroborated"]) for e in rev["insights"]] == [(hook["id"], [stored["id"]])]


def test_aegis_capture_insight_rejects_invalid_arguments_and_path_traversal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    ws = _make_workspace(tmp_path / "ws")

    empty_res = execute_tool("aegis_capture_insight", {"workspace": str(ws), "quote": "   "})
    assert empty_res["status"] == "FAIL"

    traversal_res = execute_tool(
        "aegis_capture_insight",
        {"workspace": str(ws), "quote": "Do not escape workspace", "paths": ["../outside.py"]},
    )
    assert traversal_res["status"] == "FAIL"

    unknown_arg_res = execute_tool(
        "aegis_capture_insight",
        {"workspace": str(ws), "quote": "Valid quote", "extra": 123},
    )
    assert unknown_arg_res["status"] == "FAIL"
    assert read_insight_rows(ws, home=home) == []


# ── R-evidence-32: a write tool reachable by the agent has bounded cost per call and per session ──

@pytest.fixture
def bounded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    return _make_workspace(tmp_path / "ws"), home


def _capture(ws: Path, quote: str, session=None, **extra):
    args = {"workspace": str(ws), "_host": "claude-code", "quote": quote, **extra}
    if session is not None:
        args["_session"] = session
    return execute_tool("aegis_capture_insight", args)


def test_the_session_cap_refuses_the_next_capture_and_writes_nothing(bounded, monkeypatch):
    ws, home = bounded
    monkeypatch.setattr(insights_mod, "MAX_CAPTURES_PER_SESSION", 3)
    for i in range(3):
        assert _capture(ws, f"prefer explicit names {i}", "s1", paths=["src/service.py"])["status"] == "OK"
    refused = _capture(ws, "prefer explicit names 3", "s1", paths=["src/service.py"])
    assert refused["status"] == "FAIL"
    assert "at most 3 insights per session" in refused["error"]
    assert len(read_insight_rows(ws, home=home)) == 3
    assert _capture(ws, "a new session may capture", "s2", paths=["src/service.py"])["status"] == "OK"


def test_hook_prompts_never_consume_the_session_cap(bounded, monkeypatch):
    ws, home = bounded
    monkeypatch.setattr(insights_mod, "MAX_CAPTURES_PER_SESSION", 3)
    for i in range(5):
        record_hook_prompt("claude-code", {"prompt": f"No, stop doing thing {i} again", "session_id": "s1",
                                           "cwd": str(ws)}, workspace=ws, home=home)
    for i in range(3):
        assert _capture(ws, f"unrelated preference {i}", "s1", paths=["src/service.py"])["status"] == "OK"
    assert _capture(ws, "one too many", "s1", paths=["src/service.py"])["status"] == "FAIL"


@pytest.mark.parametrize("paths", [["p" * 5000] * 100, [f"src/f{i}.py" for i in range(21)], ["s" * 513]],
                         ids=["huge", "21-paths", "513-chars"])
def test_paths_over_the_bounds_fail_with_no_row(bounded, paths):
    ws, home = bounded
    result = _capture(ws, "keep functions small", "s1", paths=paths)
    assert result["status"] == "FAIL"
    assert "at most 20" in result["error"] and "512" in result["error"]
    assert read_insight_rows(ws, home=home) == []


def test_twenty_paths_are_kept(bounded):
    ws, home = bounded
    paths = [f"src/f{i:02d}.py" for i in range(20)]
    result = _capture(ws, "keep functions small", "s1", paths=paths)
    assert result["status"] == "OK"
    assert result["paths"] == sorted(paths)


# On Windows the absolute path passes MAX_PATH (260), does not resolve and is refused by
# confinement, which runs after the length bound this test is about.
@pytest.mark.skipif(sys.platform == "win32", reason="an absolute path over MAX_PATH does not resolve on Windows")
def test_a_path_of_512_characters_is_kept(bounded):
    ws, home = bounded
    path = "src/" + "d" * 505 + ".py"
    assert len(path) == 512
    result = _capture(ws, "keep functions small", "s1", paths=[path])
    assert result["status"] == "OK"
    assert result["paths"] == [path]


def test_the_derived_dirty_paths_are_cut_to_twenty_and_counted(bounded):
    ws, home = bounded
    for i in range(40):
        (ws / "src" / f"new_{i:02d}.py").write_text("x = 1\n", encoding="utf-8")
    result = _capture(ws, "keep functions small", "s1")
    assert result["status"] == "OK" and result["psrc"] == "dirty"
    assert result["paths"] == [f"src/new_{i:02d}.py" for i in range(20)]
    row, = read_insight_rows(ws, home=home)
    assert row["paths_dropped"] == 20


def test_sessionless_callers_share_one_bucket_capped_at_50(bounded):
    ws, home = bounded
    assert insights_mod.MAX_CAPTURES_PER_SESSION == 50
    for i in range(50):
        assert _capture(ws, f"sessionless preference {i}", paths=["src/service.py"])["status"] == "OK"
    assert _capture(ws, "the 51st", paths=["src/service.py"])["status"] == "FAIL"
    # A session has its own bucket; the shared one does not spill into it.
    assert _capture(ws, "with a session", "s1", paths=["src/service.py"])["status"] == "OK"
    with pytest.raises(insights_mod.CaptureLimitReached):
        insights_mod.capture_suggestion(ws, "direct core call", paths=["src/service.py"], home=home)


def test_the_sixth_capture_within_a_minute_is_rate_limited(bounded, monkeypatch):
    ws, _home = bounded
    monkeypatch.setattr(server, "_canonical_workspace", str(ws))
    monkeypatch.setattr(server, "_workspace_error", None)
    server.handle_request({"jsonrpc": "2.0", "id": 0, "method": "initialize",
                           "params": {"clientInfo": {"name": "claude-code", "version": "1.0"}}})
    limit = server._RATE_LIMITS["aegis_capture_insight"][0]
    assert limit == 5

    def call(i):
        return server.handle_request({"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {
            "name": "aegis_capture_insight", "arguments": {"quote": f"preference {i}", "paths": ["src/service.py"]}}})

    for i in range(1, limit + 1):
        assert call(i)["result"]["isError"] is False
    response = call(99)
    assert response["error"]["code"] == -32000
    assert response["error"]["message"].startswith("Rate limit exceeded for 'aegis_capture_insight'")


def test_the_schema_and_description_publish_the_bounds():
    tool = next(t for t in TOOL_DEFINITIONS if t["name"] == "aegis_capture_insight")
    paths = tool["inputSchema"]["properties"]["paths"]
    assert (paths["maxItems"], paths["items"]) == (20, {"type": "string", "maxLength": 512})
    assert "50 captures per session" in tool["description"]
    assert "5 calls per 60 seconds" in tool["description"]
