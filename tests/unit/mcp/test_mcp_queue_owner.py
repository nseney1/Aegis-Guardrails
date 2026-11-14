"""Owner launch entry has no caller role/root override and fixed errors."""
import json
import io
from types import SimpleNamespace

import pytest

import aegis_mcp.queue_role as queue_role
import aegis_mcp.queue_owner as queue_owner
import aegis_mcp.server as server
from tests.unit.mcp.test_mcp_queue_role import owner_factory



@pytest.mark.parametrize("arguments", [[], ["alpha", "extra"], ["../alpha"],
    ["token=private-value"], ["alpha\n"], ["x" * 65], ["--role=orchestrator"]])
def test_owner_launch_closed_arguments(arguments, capsys):

    assert queue_owner.main(arguments) == 2
    assert capsys.readouterr().err == "aegis-mcp-queue: invalid_arguments\n"


def test_owner_launch_stdio_public_surface(owner_factory, tmp_path, monkeypatch, capsys):
    role, root, path, workspace, policy = owner_factory()

    requests = [{"jsonrpc": "2.0", "id": 1, "method": "initialize"},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}]
    frames_in = b"".join((json.dumps(v) + "\n").encode() for v in requests)
    monkeypatch.setattr(server, "input_stream", lambda stream: io.BytesIO(frames_in))
    assert queue_owner.main(["alpha"]) == 0
    frames = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [t["name"] for t in frames[1]["result"]["tools"]] == ["aegis_team_queue", "aegis_team_queue_claim"]
    assert server._session_id is None


def test_owner_launch_failure_is_fixed(owner_factory, tmp_path, monkeypatch, capsys):
    role, root, path, workspace, policy = owner_factory()

    path.unlink()
    assert queue_owner.main(["alpha"]) == 1
    assert capsys.readouterr().err == "aegis-mcp-queue: role_missing\n"
