"""Unit tests for MCP aegis_capture_insight tool."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess

import pytest

from aegis_core.insights import read_insight_rows, record_hook_prompt, review_insights
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


def test_aegis_capture_insight_records_suggestion_and_upgrades_on_hook_match(
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

    # Unconfirmed suggestion never counts in review clusters
    rev = review_insights(ws, home=home)
    assert rev["clusters"] == []
    assert len(rev["suggestions"]) == 1

    # 2. Hook captures a prompt in session 'mcp-sess-2' containing the quote -> upgrades to W2
    record_hook_prompt(
        ws,
        "claude-code",
        {
            "prompt": "No, stop using raw os.system calls in src/service.py!",
            "session_id": "mcp-sess-2",
            "cwd": str(ws),
        },
        home=home,
    )
    res_upgraded = execute_tool(
        "aegis_capture_insight",
        {
            "workspace": str(ws),
            "_host": "claude-code",
            "_session": "mcp-sess-2",
            "quote": "stop using raw os.system calls in src/service.py",
            "paths": ["src/service.py"],
        },
    )
    assert res_upgraded["status"] == "OK"
    assert res_upgraded["level"] == "W2"


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
