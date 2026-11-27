"""Successful MCP text JSON is compact without changing payloads or refusals."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil

import pytest

from aegis_core.workspace.base import Workspace
from aegis_mcp import server
from aegis_mcp.tools import execute_tool
from tests.helpers_manager import active, manager_root, prepare


REPO = Path(__file__).resolve().parents[3]
DESCRIPTION = 'Keep spaces: {"text": "café, x: y", "values": [true, null]}\nnext\t"quoted"\\path'


def _call(name, arguments):
    return server.handle_request({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                                  "params": {"name": name, "arguments": arguments}})


def _wire_response(response, capsys):
    server.send_response(response)
    wire = capsys.readouterr().out
    # Outer JSON-RPC framing keeps its existing serialization and newline.
    assert wire == json.dumps(response) + "\n"
    return json.loads(wire)


def _assert_compact(response, expected, capsys):
    result = _wire_response(response, capsys)["result"]
    assert result["isError"] is False
    assert [item["type"] for item in result["content"]] == ["text"]
    text = result["content"][0]["text"]
    decoded = json.loads(text)
    # Compare every field and string, including whitespace inside string values.
    baseline = json.dumps(expected).encode("utf-8")
    assert json.dumps(decoded).encode("utf-8") == baseline
    assert text == json.dumps(expected, separators=(",", ":"))
    assert len(text.encode("utf-8")) < len(baseline)
    return decoded


@pytest.fixture
def repository(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    # Read this checkout's real tracked rule files normally; no Git history needed.
    shutil.copytree(REPO / ".aegis" / "rules", tmp_path / ".aegis" / "rules")
    monkeypatch.setattr(server, "_canonical_workspace", str(tmp_path))
    server.handle_request({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    return Workspace(tmp_path)


def test_repository_never_reads_developer_registry(tmp_path, monkeypatch, request, capsys):
    developer_home = tmp_path / "developer-home"
    sentinel = developer_home / ".aegis" / "workspaces.json"
    sentinel.parent.mkdir(parents=True)
    sentinel.write_text('{"v": 1, "workspaces": []}', encoding="utf-8")
    monkeypatch.setenv("HOME", str(developer_home))
    monkeypatch.setenv("USERPROFILE", str(developer_home))
    read_registry = server.read_registry
    reads = []

    def checked_registry(path):
        assert Path(path) != sentinel, "developer registry must not be read"
        reads.append(Path(path))
        return read_registry(path)

    # Patch the server's filesystem boundary, never shared OS or Path methods.
    monkeypatch.setattr(server, "read_registry", checked_registry)
    # Start the repository fixture only after establishing the developer HOME.
    workspace = request.getfixturevalue("repository")
    expected = execute_tool("aegis_list_rules", {"workspace": workspace})
    _assert_compact(_call("aegis_list_rules", {}), expected, capsys)
    assert reads == [tmp_path / "home" / ".aegis" / "workspaces.json"]


@pytest.mark.parametrize("name,arguments", [
    ("aegis_list_rules", {}),
    ("aegis_list_rules", {"view": "summary"}),
    ("aegis_list_rules", {"view": "ids"}),
    ("aegis_create_rule", {"description": DESCRIPTION}),
])
def test_real_repository_responses_preserve_nested_json(repository, capsys, name, arguments):
    expected = execute_tool(name, {"workspace": repository, **arguments})
    if name == "aegis_list_rules":
        assert expected["rules"]
    decoded = _assert_compact(_call(name, arguments), expected, capsys)
    if name == "aegis_create_rule":
        assert DESCRIPTION in decoded["prompt"]


@pytest.fixture
def manager(manager_root, monkeypatch):
    # These helpers create their own isolated history and real signed activation.
    prepared = prepare(manager_root)
    service = active(prepared)
    monkeypatch.setattr(server, "_manager_config", str(prepared["config"]))
    monkeypatch.setattr(server, "_manager_digest",
                        hashlib.sha256(prepared["config"].read_bytes()).hexdigest())
    server.handle_request({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    return service


def test_real_manager_response_preserves_nested_json(manager, capsys):
    expected = manager.list_rules()
    assert expected["rules"]
    _assert_compact(_call("aegis_list_rules", {}), expected, capsys)


def test_repository_handler_refusal_text_and_framing_unchanged(repository, capsys):
    expected = {"error": "'description' must be a non-empty string.", "status": "FAIL"}
    response = _wire_response(_call("aegis_create_rule", {}), capsys)
    assert response == {"jsonrpc": "2.0", "id": 7, "result": {
        "content": [{"type": "text", "text": json.dumps(expected)}], "isError": True}}


def test_manager_execution_refusal_text_and_framing_unchanged(manager, monkeypatch, capsys):
    monkeypatch.setattr(server, "_manager_digest", "0" * 64)
    response = _wire_response(_call("aegis_list_rules", {}), capsys)
    assert response == {"jsonrpc": "2.0", "id": 7, "result": {
        "content": [{"type": "text", "text": json.dumps({"status": "FAIL", "error": "config_mismatch"})}],
        "isError": True}}


@pytest.mark.parametrize("mode", ["repository", "manager"])
def test_invalid_arguments_keep_json_rpc_error_framing(mode, tmp_path, monkeypatch, capsys):
    if mode == "manager":
        monkeypatch.setattr(server, "_manager_config", str(tmp_path / "unread.json"))
    server.handle_request({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    response = _wire_response(_call("aegis_list_rules", []), capsys)
    message = ("Tool arguments must be an object." if mode == "repository" else
               "manager argument arguments must be object")
    assert response == {"jsonrpc": "2.0", "id": 7,
                        "error": {"code": -32602, "message": message}}
