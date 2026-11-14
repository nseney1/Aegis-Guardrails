"""Read-only queue MCP uses the same service and bounded refusals as the CLI."""
import json
import os
import shutil
import subprocess

import pytest

import aegis_mcp.queue_role as queue_role
from tests.unit.mcp.test_mcp_queue_role import owner_factory

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


def test_owner_claim_policy_and_revision_retry(owner_factory, tmp_path, monkeypatch):
    from tests.unit.mcp.test_mcp_queue_role import start_owner, claim

    role, root, path, repo, policy = owner_factory()
    require_store(repo)
    added = queue.add(repo, {"id": "ONE", "title": "Work", "paths": ["src/**"], "capabilities": ["core"]})
    start_owner()
    arguments = {"id": "ONE", "expect": added["item"]["revision"], "lane": "alpha"}
    result = claim(arguments)
    assert not result["refused"], result
    assert result["item"]["lane"] == "alpha"
    assert result["item"]["branch"] == "lane/alpha"
    assert result["item"]["expires_at"] is not None
    assert claim(arguments)["reason"] == "stale_revision"


def _workspace_spelling(root, style):
    if style == "trailing":
        return str(root) + "/"
    if style == "separators":
        return str(root.parent) + "//" + root.name
    if style == "dot":
        return str(root.parent) + "/./" + root.name
    if style == "leading":
        return "/" + str(root)
    return str(root)


@pytest.mark.parametrize("style", ["canonical", "trailing", "separators", "dot", "leading"])
def test_owner_workspace_spellings_claim_and_pin_original_bytes(owner_factory, style):
    import hashlib
    from tests.unit.mcp.test_mcp_queue_role import start_owner, claim

    role, root, path, repo, policy = owner_factory()
    require_store(repo)
    policy["workspace"] = _workspace_spelling(repo, style)
    raw = (json.dumps(policy, indent=1) + "\n").encode("utf-8")
    path.write_bytes(raw)
    added = queue.add(repo, {"id": "ONE", "title": "Work", "paths": ["src/**"], "capabilities": []})
    assert not added["refused"], added
    start_owner()
    record = json.loads(next((root / "sessions").glob("*.json")).read_text())
    assert record["registration_sha256"] == hashlib.sha256(raw).hexdigest()
    assert path.read_bytes() == raw
    _, listed = call({})
    assert [item["id"] for item in listed["items"]] == ["ONE"]
    arguments = {"id": "ONE", "expect": added["item"]["revision"], "lane": "alpha"}
    result = claim(arguments)
    assert not result["refused"], result
    assert claim(arguments)["reason"] == "stale_revision"
    assert path.read_bytes() == raw
    # Equivalent policy/path content cannot replace the exact startup bytes.
    policy["workspace"] = str(repo)
    path.write_text(json.dumps(policy), encoding="utf-8")
    assert claim(arguments)["reason"] == "role_stale"


@pytest.mark.parametrize("style", ["parent", "symlink"])
def test_owner_workspace_unsafe_spellings_keep_fixed_refusal(owner_factory, tmp_path, capsys, style):
    from conftest import symlink_or_skip
    from aegis_mcp import queue_owner

    role, root, path, repo, policy = owner_factory()
    if style == "parent":
        policy["workspace"] = str(repo / ".." / repo.name)
    else:
        link = tmp_path / "workspace-link"
        symlink_or_skip(repo, link, target_is_directory=True)
        policy["workspace"] = str(link)
    raw = json.dumps(policy).encode("utf-8")
    path.write_bytes(raw)
    assert queue_owner.main(["alpha"]) == 1
    assert capsys.readouterr().err == "aegis-mcp-queue: role_invalid\n"
    assert path.read_bytes() == raw
    assert not (root / "sessions").exists()


def test_owner_claim_forbidden_lane_and_dispatch_retry(owner_factory, tmp_path, monkeypatch):
    from tests.unit.mcp.test_mcp_queue_role import start_owner, claim

    role, root, path, repo, policy = owner_factory()
    require_store(repo)
    added = queue.add(repo, {"id": "ONE", "title": "Work", "paths": ["src/**"], "capabilities": []})
    start_owner()
    args = {"id": "ONE", "expect": added["item"]["revision"], "lane": "foreign"}
    assert claim(args)["reason"] == "role_forbidden"
    args["lane"] = "alpha"
    original = queue.claim
    def unavailable(*args, **kwargs):
        raise OSError("token=private-value")
    monkeypatch.setattr(queue, "claim", unavailable)
    result = claim(args)
    assert result["reason"] == "queue_io_unavailable"
    assert "private-value" not in json.dumps(result)
    monkeypatch.setattr(queue, "claim", original)
    assert not claim(args)["refused"]


@pytest.mark.parametrize("reason", ["item_missing", "invalid_queue_state", "stale_revision", "blocked", "capability_mismatch"])
def test_authorized_claim_refusals_preserve_state_and_recover(owner_factory, reason):
    from tests.unit.mcp.test_mcp_queue_role import start_owner, claim

    role, root, path, repo, policy = owner_factory()
    require_store(repo)
    item = {"id": "ONE", "title": "Work", "paths": ["src/**"], "capabilities": []}
    if reason == "blocked":
        item["hold"] = "Owner review"
    elif reason == "capability_mismatch":
        item["capabilities"] = ["other"]
    revision = "a" * 64
    if reason != "item_missing":
        added = queue.add(repo, item)
        assert not added["refused"], added
        revision = added["item"]["revision"]
    state = repo / ".aegis" / "state" / "team-queue.json"
    if reason == "invalid_queue_state":
        state.write_text("[]")
    before = state.read_bytes() if state.exists() else None
    start_owner()
    result = claim({"id": "ONE", "expect": "b" * 64 if reason == "stale_revision" else revision, "lane": "alpha"})
    assert result["reason"] == reason and result["refused"], result
    assert (state.read_bytes() if state.exists() else None) == before
    if reason == "invalid_queue_state":
        state.unlink()  # Remove only this test's injected corrupt record.
    corrected = queue.add(repo, {"id": "TWO", "title": "Next", "paths": ["src/**"], "capabilities": []})
    assert not corrected["refused"], corrected
    assert not claim({"id": "TWO", "expect": corrected["item"]["revision"], "lane": "alpha"})["refused"]


def test_owner_expiry_rechecked_after_queue_lock(owner_factory, tmp_path, monkeypatch):
    from contextlib import contextmanager
    from types import SimpleNamespace
    from tests.unit.mcp.test_mcp_queue_role import start_owner, claim

    role, root, path, repo, policy = owner_factory()
    require_store(repo)
    added = queue.add(repo, {"id": "ONE", "title": "Work", "paths": ["src/**"], "capabilities": []})
    start_owner()
    expires = server._queue_grant.record["expires_at"]
    clock = [expires - 1]
    real = role.storage
    @contextmanager
    def delayed_lock(*args, **kwargs):
        with real.locked(*args, **kwargs) as held:
            clock[0] = expires
            yield held
    monkeypatch.setattr(queue_role, "time", SimpleNamespace(time=lambda: clock[0]))
    monkeypatch.setattr(queue_role, "storage", SimpleNamespace(
        locked=delayed_lock, file_lock=real.file_lock, LockTimeoutError=real.LockTimeoutError))
    result = claim({"id": "ONE", "expect": added["item"]["revision"], "lane": "alpha"})
    assert result["reason"] == "role_stale"
    assert queue.list(repo)["items"][0]["state"] == "queued"


def _owner_claim_worker(arguments, barrier, results):
    from tests.unit.mcp.test_mcp_queue_role import start_owner, claim

    start_owner()
    barrier.wait(timeout=10)
    results.put(claim(arguments))


@pytest.mark.parametrize("workspace_style", ["canonical", "trailing", "separators", "dot"])
def test_two_owner_processes_claim_one_revision(owner_factory, tmp_path, monkeypatch, workspace_style):
    import multiprocessing

    role, root, path, repo, policy = owner_factory()
    require_store(repo)
    policy["workspace"] = _workspace_spelling(repo, workspace_style)
    path.write_text(json.dumps(policy), encoding="utf-8")
    added = queue.add(repo, {"id": "ONE", "title": "Work", "paths": ["src/**"], "capabilities": []})
    args = {"id": "ONE", "expect": added["item"]["revision"], "lane": "alpha"}
    context = multiprocessing.get_context("fork")
    barrier, results = context.Barrier(2), context.Queue()
    processes = [context.Process(target=_owner_claim_worker, args=(args, barrier, results)) for _ in range(2)]
    try:
        for process in processes:
            process.start()
        values = [results.get(timeout=15) for _ in processes]
        for process in processes:
            process.join(timeout=10)
            assert not process.is_alive() and process.exitcode == 0
        assert sum(not value["refused"] for value in values) == 1
        assert [value["reason"] for value in values if value["refused"]] == ["stale_revision"]
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join(timeout=5)
        results.close()
        results.join_thread()


def _owner_revocation_worker(arguments, ready, proceed, results):
    from tests.unit.mcp.test_mcp_queue_role import start_owner, claim

    start_owner()
    ready.set()
    assert proceed.wait(timeout=10)
    results.put(claim(arguments))


def test_owner_revocation_precedes_waiting_claim(owner_factory, tmp_path):
    import multiprocessing

    role, root, path, repo, policy = owner_factory()
    require_store(repo)
    added = queue.add(repo, {"id": "ONE", "title": "Work", "paths": ["src/**"], "capabilities": []})
    args = {"id": "ONE", "expect": added["item"]["revision"], "lane": "alpha"}
    context = multiprocessing.get_context("fork")
    ready, proceed, results = context.Event(), context.Event(), context.Queue()
    process = context.Process(target=_owner_revocation_worker, args=(args, ready, proceed, results))
    try:
        process.start()
        assert ready.wait(timeout=10)
        with role.authority():
            policy["role"] = "reviewer"
            path.write_text(json.dumps(policy), encoding="utf-8")
            proceed.set()
        assert results.get(timeout=15)["reason"] == "role_stale"
        process.join(timeout=10)
        assert not process.is_alive() and process.exitcode == 0
        assert queue.list(repo)["items"][0]["state"] == "queued"
    finally:
        if process.is_alive():
            process.terminate()
            process.join(timeout=5)
        results.close()
        results.join_thread()


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
