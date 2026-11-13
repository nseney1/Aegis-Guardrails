"""Read-only queue MCP uses the same service and bounded refusals as the CLI."""
import json
import os
import shutil
import subprocess

import pytest

from aegis_core import team_queue as queue
from aegis_cli.cli import main
import aegis_mcp.server as server
from aegis_mcp.tools import execute_tool


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    (root / ".aegis" / "rules").mkdir(parents=True)
    (root / ".aegis" / "team.json").write_text(
        json.dumps({"v": 1, "lanes": {"alpha": ["src/**"]}}), encoding="utf-8")
    home = tmp_path / "home"
    home.mkdir()
    # Restored by the repository's autouse hermetic environment fixture.
    os.environ.update({"HOME": str(home), "USERPROFILE": str(home)})
    monkeypatch.setattr(server, "_canonical_workspace", str(root))
    monkeypatch.setattr(server, "_workspace_error", None)
    monkeypatch.setattr(server, "_session_id", None)
    server.handle_request({"jsonrpc": "2.0", "id": 0, "method": "initialize"})
    return root


def call(arguments):
    response = server.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "aegis_team_queue", "arguments": arguments}})
    assert "error" not in response, response
    result = response["result"]
    return result, json.loads(result["content"][0]["text"])


def require_store(root):
    if not queue.descriptor_supported():
        pytest.skip("requires descriptor-relative nofollow operations")
    if shutil.which("git") is None:
        pytest.skip("requires git")
    subprocess.run(["git", "init", "-q", str(root)], check=True)


def test_queue_tool_is_closed_and_read_only(workspace):
    result = server.handle_request({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    tool = next(t for t in result["result"]["tools"] if t["name"] == "aegis_team_queue")
    assert tool["annotations"] == {"readOnlyHint": True, "destructiveHint": False,
        "idempotentHint": True, "openWorldHint": False, "title": "Team Queue"}
    assert tool["inputSchema"]["additionalProperties"] is False
    assert set(tool["inputSchema"]["properties"]) == {"capabilities", "include_done"}


@pytest.mark.parametrize("include_done", [False, True])
def test_mcp_cli_service_parity_and_no_writes(workspace, capsys, include_done):
    require_store(workspace)
    added = queue.add(workspace, {"id": "ONE", "title": "Work", "paths": ["src/**"], "capabilities": ["core"]})
    claimed = queue.claim(workspace, "ONE", expect=added["item"]["revision"], lane="alpha", capabilities=["core"])
    assert not claimed["refused"], claimed
    assert not queue.done(workspace, "ONE", expect=claimed["item"]["revision"], lane="alpha")["refused"]
    before = {p: p.read_bytes() for p in (workspace / ".aegis").rglob("*") if p.is_file()}
    result, payload = call({"capabilities": ["core"], "include_done": include_done})
    args = ["--workspace", str(workspace), "team", "queue", "list", "--capability", "core", "--json"]
    if include_done:
        args.append("--include-done")
    assert main(args) == 0
    expected = json.loads(capsys.readouterr().out)
    expected.pop("checked_at")
    payload.pop("checked_at")
    assert result["isError"] is False and payload == expected
    assert len(payload["items"]) == int(include_done)
    assert {p: p.read_bytes() for p in (workspace / ".aegis").rglob("*") if p.is_file()} == before


@pytest.mark.parametrize("arguments", [{"action": "claim"}, {"item": "token=private-value"},
    {"capabilities": "core"}, {"capabilities": None}, {"capabilities": ["token=private-value"]},
    {"capabilities": ["x"] * 129}, {"include_done": "true"}, {"include_done": None}])
def test_mcp_queue_invalid_arguments_are_fixed_and_do_not_write(workspace, arguments):
    result, payload = call(arguments)
    assert payload["refused"] and payload["reason"] == "invalid_arguments"
    assert payload["exit_code"] == 2 and payload["next_action"]
    assert result["isError"] is True
    assert "private-value" not in json.dumps(payload)
    assert not (workspace / ".aegis" / "state").exists()


def test_mcp_unsupported_platform_and_missing_state_are_refusals(workspace, monkeypatch):
    monkeypatch.setattr(queue, "descriptor_supported", lambda: False)
    _, payload = call({})
    assert payload["reason"] == "unsupported_platform" and payload["exit_code"] == 1
    assert not (workspace / ".aegis" / "state").exists()


def test_direct_queue_bad_types_and_client_injection_are_refused(workspace):
    for args in ([], None, {"workspace": "token=private-value"}):
        payload = execute_tool("aegis_team_queue", args, client_arguments=True)
        assert payload["reason"] == "invalid_arguments" and payload["exit_code"] == 2
        assert "private-value" not in json.dumps(payload)


def test_mcp_list_preserves_compacted_completion_history(workspace):
    require_store(workspace)
    added = queue.add(workspace, {"id": "ONE", "title": "Work", "paths": ["src/**"], "capabilities": []})
    claimed = queue.claim(workspace, "ONE", expect=added["item"]["revision"], lane="alpha", branch="lane/alpha")
    assert not claimed["refused"]
    assert not queue.done(workspace, "ONE", expect=claimed["item"]["revision"], lane="alpha")["refused"]
    assert queue.compact(workspace)["removed_ids"] == ["ONE"]
    state = workspace / ".aegis" / "state" / "team-queue.json"
    before = state.read_bytes()
    for include_done in (False, True):
        result, actual = call({"include_done": include_done})
        expected = queue.list(workspace, include_done=include_done)
        actual.pop("checked_at")
        expected.pop("checked_at")
        assert result["isError"] is False and actual == expected
        assert actual.get("completed_ids", []) == (["ONE"] if include_done else [])
    assert state.read_bytes() == before


@pytest.mark.parametrize("arguments", [{"workspace": "token=private-value"},
    {"files": ["/other/registered/repo/a.py"]}, {"_session": "private-value"},
    [], None, "token=private-value", {"include_done": "private-value"}, {"capabilities": ["private-value/"]}])
def test_queue_client_validation_precedes_binding(workspace, monkeypatch, arguments):
    def unexpected(*args, **kwargs):
        raise AssertionError("binding must not run for invalid client input")
    monkeypatch.setattr(server, "_bind", unexpected)
    result, payload = call(arguments)
    assert result["isError"] is True
    assert payload["schema"] == "aegis.team.queue.list/v1"
    assert payload["reason"] == "invalid_arguments" and payload["exit_code"] == 2
    assert "private-value" not in json.dumps(payload)
    assert not (workspace / ".aegis" / "state").exists()


@pytest.mark.parametrize("mode", ["missing", "conflict"])
def test_queue_binding_failures_use_fixed_envelope_without_raw_pin(workspace, tmp_path, monkeypatch, mode):
    if mode == "missing":
        monkeypatch.setattr(server, "_canonical_workspace", str(tmp_path / "token=private-value" / "missing"))
    else:
        other = tmp_path / "token=private-value"
        (other / ".aegis" / "rules").mkdir(parents=True)
        monkeypatch.setattr(server, "_host_roots", (str(other),))
    result, payload = call({})
    assert result["isError"] is True
    assert payload["schema"] == "aegis.team.queue.list/v1"
    assert payload["reason"] == "queue_io_unavailable" and payload["exit_code"] == 1
    assert "private-value" not in json.dumps(payload)
    assert not (workspace / ".aegis" / "state").exists()


def test_queue_held_workspace_validates_client_arguments_first(workspace, monkeypatch):
    from aegis_core.workspace.binding import WorkspaceBinding
    monkeypatch.setattr(server, "_workspace_error", WorkspaceBinding(
        status="hold", reason="private-value", message="token=private-value"))
    for args, reason in (([], "invalid_arguments"), ({}, "queue_io_unavailable")):
        result, payload = call(args)
        assert result["isError"] is True and payload["reason"] == reason
        assert payload["schema"] == "aegis.team.queue.list/v1"
        assert "private-value" not in json.dumps(payload)


@pytest.mark.parametrize("stage", ["binding", "dispatch"])
def test_queue_transport_io_failures_are_fixed_and_retryable(workspace, monkeypatch, capsys, stage):
    binding = server._bind
    def unavailable(*args, **kwargs):
        raise OSError("token=private-value")
    if stage == "binding":
        monkeypatch.setattr(server, "_bind", unavailable)
    else:
        monkeypatch.setattr(server, "execute_tool", unavailable)
    result, payload = call({})
    assert result["isError"] is True and payload["reason"] == "queue_io_unavailable"
    assert payload["exit_code"] == 1 and payload["next_action"]
    assert "private-value" not in json.dumps(payload) + capsys.readouterr().err
    monkeypatch.setattr(server, "_bind", binding)
    monkeypatch.setattr(server, "execute_tool", execute_tool)
    result, payload = call({})
    if queue.descriptor_supported():
        assert result["isError"] is False and not payload["refused"]
    else:
        assert payload["reason"] == "unsupported_platform"
