"""Each role sees only its own read-only workspace tools, and only when a store is configured."""
import hashlib
import json
import os
import subprocess
import sys

import pytest

from tests.integration.test_hierarchy_mailbox import HELPER, git, invoke
from tests.integration.test_hierarchy_workspace import Workspace, clone_pair, write_lease


MAILBOX_TOOLS = {"mailbox_inbox", "mailbox_publish", "mailbox_ack_handoff"}
ENDPOINTS = {"a/front-door": {}, "a/orchestrator": {}, "a/root": {}, "a/lane/f2": {"kind": "implementer"},
             "a/lane/integration": {"kind": "integrator"}, "a/lane/review": {"kind": "reviewer"}}
ROLE_TOOLS = {
    "a/front-door": {"workspace_initiative"},
    "a/orchestrator": {"workspace_capacity", "workspace_initiative"},
    "a/lane/f2": {"workspace_path_overlap"},
    "a/lane/integration": {"workspace_path_overlap"},
    "a/lane/review": set(),
}


class Team:
    def __init__(self, tmp_path):
        self.tmp = tmp_path
        self.root = tmp_path / "mailbox"
        invoke(self.root, "init", {"schema": "aegis.hierarchy-pilot/v1", "endpoints": ENDPOINTS, "counterparts": [],
                                   "writer_limit": 3})
        for endpoint in ENDPOINTS:
            invoke(self.root, "bind", {"endpoint": endpoint, "host": "host-one", "session": endpoint,
                                       "expected_generation": 0})
        self.workspace = Workspace(tmp_path)
        self.workspace.run("init", {"writer_limit": 3, "heavy_limit": 1})

    def serve(self, endpoint, calls=(), *, store=True, initiative="own", extra=(), session=None, generation=1):
        frames = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
                  {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}]
        frames += [{"jsonrpc": "2.0", "id": index + 3, "method": "tools/call",
                    "params": {"name": name, "arguments": arguments}} for index, (name, arguments) in enumerate(calls)]
        argv = [sys.executable, "-I", str(HELPER), "--root", str(self.root), "serve", "--endpoint", endpoint,
                "--host", "host-one", "--session", session or endpoint, "--generation", str(generation)]
        if store:
            argv += ["--workspace-store", str(self.workspace.store), "--initiative", initiative]
        return subprocess.run([*argv, *extra], input="".join(json.dumps(f) + "\n" for f in frames), capture_output=True,
                              text=True, timeout=20, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})

    def responses(self, *args, **kwargs):
        result = self.serve(*args, **kwargs)
        assert result.returncode == 0, result.stdout + result.stderr
        assert not result.stderr
        return [json.loads(line) for line in result.stdout.splitlines()]

    def tools(self, endpoint, **kwargs):
        return {tool["name"]: tool for tool in self.responses(endpoint, **kwargs)[1]["result"]["tools"]}

    def call(self, endpoint, name, arguments=None):
        response = self.responses(endpoint, [(name, arguments or {})])[-1]["result"]
        return response.get("isError", False), json.loads(response["content"][0]["text"])


@pytest.fixture
def team(tmp_path):
    built = Team(tmp_path)
    built.workspace.register("own", priority=5)
    return built


@pytest.mark.parametrize("endpoint", sorted(ROLE_TOOLS))
def test_without_a_store_every_role_keeps_exactly_the_mailbox_tools(team, endpoint):
    assert set(team.tools(endpoint, store=False)) == MAILBOX_TOOLS


@pytest.mark.parametrize("endpoint,expected", sorted(ROLE_TOOLS.items()))
def test_with_a_store_each_role_gets_only_its_own_tools(team, endpoint, expected):
    assert set(team.tools(endpoint)) == MAILBOX_TOOLS | expected


def test_workspace_tools_are_read_only_and_closed_to_extra_arguments(team):
    tools = {**team.tools("a/orchestrator"), **team.tools("a/lane/f2")}
    for name in ("workspace_capacity", "workspace_initiative", "workspace_path_overlap"):
        assert tools[name]["annotations"]["readOnlyHint"] is True
        assert tools[name]["inputSchema"]["additionalProperties"] is False


def test_no_role_is_offered_a_grant_or_mutation(team):
    names = set()
    for endpoint in ROLE_TOOLS:
        names |= set(team.tools(endpoint))
    forbidden = ("grant", "release", "claim", "register", "update", "bind", "launch", "priority", "merge")
    assert not [name for name in names if any(word in name for word in forbidden)]


@pytest.mark.parametrize("endpoint,name", [
    ("a/lane/review", "workspace_path_overlap"), ("a/lane/review", "workspace_capacity"),
    ("a/lane/f2", "workspace_capacity"), ("a/lane/f2", "workspace_initiative"),
    ("a/front-door", "workspace_capacity"), ("a/front-door", "workspace_path_overlap"),
    ("a/orchestrator", "workspace_path_overlap"),
])
def test_a_tool_outside_the_role_is_refused(team, endpoint, name):
    failed, data = team.call(endpoint, name, {"paths": ["x.txt"]} if name.endswith("overlap") else {})
    assert failed is True and data["error"] == "unknown mailbox tool: " + name


def test_a_store_is_not_reachable_without_configuration(team):
    response = team.responses("a/orchestrator", [("workspace_capacity", {})], store=False)[-1]["result"]
    assert response["isError"] is True
    assert json.loads(response["content"][0]["text"])["error"] == "unknown mailbox tool: workspace_capacity"


def test_capacity_reports_the_ledger_and_changes_nothing(team):
    team.workspace.ask("own", holder="own/lane")
    team.workspace.grant()
    team.workspace.ask("own", "heavy", "own/full-suite")
    before = {path: path.read_bytes() for path in team.workspace.store.rglob("*") if path.is_file()}
    failed, data = team.call("a/orchestrator", "workspace_capacity")
    assert failed is False
    assert data["writer"]["used"] == 1 and data["writer"]["limit"] == 3
    assert [row["holder"] for row in data["queue"]] == ["own/full-suite"]
    assert {path: path.read_bytes() for path in team.workspace.store.rglob("*") if path.is_file()} == before


def test_the_initiative_record_is_this_connections_own(team):
    team.workspace.register("other", priority=1)
    team.workspace.run("update", {"initiative": "own", "source": "owner", "blocked_by": ["other"]})
    failed, data = team.call("a/front-door", "workspace_initiative")
    assert failed is False
    assert data["id"] == "own" and data["blocked_by"] == ["other"] and data["base_moved"] is None
    failed, refused = team.call("a/front-door", "workspace_initiative", {"initiative": "other"})
    assert failed is True and "unexpected fields" in refused["error"]


def test_the_overlap_check_reports_a_real_conflict_as_a_normal_answer(team, tmp_path):
    first, second = clone_pair(tmp_path)
    team.workspace.run("update", {"initiative": "own", "source": "root", "checkouts": [str(first)]})
    team.workspace.register("peer", checkouts=[str(second)])
    write_lease(second, "peer-lane", ["src/**"])
    failed, data = team.call("a/lane/f2", "workspace_path_overlap", {"paths": ["src/value.txt"]})
    assert failed is False and data["conflict"] is True
    assert data["conflicts"][0]["initiative"] == "peer"
    failed, clear = team.call("a/lane/f2", "workspace_path_overlap", {"paths": ["docs/value.txt"]})
    assert failed is False and clear["conflict"] is False
    assert git(first, "for-each-ref", "refs/aegis/lanes") == ""


@pytest.mark.parametrize("arguments,error", [
    ({}, "missing fields"), ({"paths": []}, "invalid paths"), ({"paths": "src/**"}, "invalid paths"),
    ({"paths": ["/absolute"]}, "invalid path"), ({"paths": ["../escape"]}, "invalid path"),
    ({"paths": ["x" * 2000]}, "invalid path"), ({"paths": ["ok"] * 65}, "invalid paths"),
    ({"paths": ["ok"], "initiative": "other"}, "unexpected fields"),
])
def test_malformed_overlap_requests_are_refused(team, arguments, error):
    failed, data = team.call("a/lane/f2", "workspace_path_overlap", arguments)
    assert failed is True and error in data["error"]


def test_a_stale_binding_cannot_read_the_workspace(team):
    brief = team.tmp / "brief.md"
    brief.write_bytes(b"Handoff.\n")
    reference ={"path": str(brief), "sha256": hashlib.sha256(b"Handoff.\n").hexdigest()}
    invoke(team.root, "bind", invoke(team.root, "draft-handoff", {
        "endpoint": "a/orchestrator", "host": "host-two", "session": "new", "outgoing_stopped": True,
        "briefs": [reference]}))
    result = team.serve("a/orchestrator", [("workspace_capacity", {})])
    assert result.returncode == 2
    assert json.loads(result.stdout)["error"] == "stale or mismatched sender binding"


@pytest.mark.parametrize("flags,error", [
    (["--workspace-store", "/tmp/no-such-aegis-store"], "workspace store and initiative must be given together"),
    (["--initiative", "own"], "workspace store and initiative must be given together"),
])
def test_store_and_initiative_must_come_together(team, flags, error):
    result = team.serve("a/orchestrator", store=False, extra=flags)
    assert result.returncode == 2 and json.loads(result.stdout)["error"] == error


def test_an_unregistered_initiative_or_missing_store_stops_startup(team, tmp_path):
    result = team.serve("a/orchestrator", initiative="unlisted")
    assert result.returncode == 2
    assert json.loads(result.stdout)["error"] == "initiative is not registered: unlisted"
    result = team.serve("a/orchestrator", store=False,
                        extra=["--workspace-store", str(tmp_path / "absent"), "--initiative", "own"])
    assert result.returncode == 2
    assert json.loads(result.stdout)["error"] == "workspace store is not initialized"


def test_a_damaged_store_fails_on_workspace_tools_and_leaves_the_mailbox_working(team):
    """A session must keep its mail even when root's records are damaged, and the damage still shows loudly."""
    (team.workspace.store / "events" / "00000002.json").write_text("{truncated")
    result = team.serve("a/orchestrator")
    assert result.returncode == 0, result.stdout
    assert not result.stderr


def test_a_store_damaged_after_startup_fails_loudly_for_that_call(team):
    process = subprocess.Popen(
        [sys.executable, "-I", str(HELPER), "--root", str(team.root), "serve", "--endpoint", "a/orchestrator",
         "--host", "host-one", "--session", "a/orchestrator", "--generation", "1",
         "--workspace-store", str(team.workspace.store), "--initiative", "own"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})

    def call(identifier, method, params=None):
        process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": identifier, "method": method, "params": params or {}}) + "\n")
        process.stdin.flush()
        return json.loads(process.stdout.readline())

    try:
        assert call(1, "initialize")["result"]["serverInfo"]["name"] == "aegis-hierarchy-mailbox"
        first = call(2, "tools/call", {"name": "workspace_capacity", "arguments": {}})["result"]
        assert "isError" not in first
        (team.workspace.store / "events" / "00000002.json").write_text("{truncated")
        second = call(3, "tools/call", {"name": "workspace_capacity", "arguments": {}})["result"]
        assert second["isError"] is True
        assert "malformed workspace event" in json.loads(second["content"][0]["text"])["error"]
    finally:
        process.stdin.close()
        process.wait(timeout=5)
        process.stdout.close()
        process.stderr.close()
