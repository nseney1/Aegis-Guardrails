"""Role capabilities hold at public provisioning and direct MCP entry points."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from tests.integration.test_hierarchy_board import BOARD, BOARD_TOOLS
from tests.integration.test_hierarchy_mailbox import HELPER, invoke
from tests.integration.test_hierarchy_provision import Setup, provision


pytestmark = pytest.mark.skipif(os.name == "nt", reason="hierarchy profiles use POSIX paths and modes")


@pytest.fixture
def setup(tmp_path):
    built = Setup(tmp_path)
    provision("init", built.init_request(roles=["router", "decider"]))
    return built


def snapshot(folder):
    return {str(path.relative_to(folder)): path.read_bytes() for path in folder.rglob("*") if path.is_file()}


@pytest.mark.parametrize("host", ["claude-code", "codex-cli", "codex"])
@pytest.mark.parametrize("endpoint,tool,role", [
    ("pilot/lane/review", "Write", "reviewer"),
    ("pilot/router", "Read", "router"),
    ("pilot/decider", "Edit", "decider"),
])
def test_forbidden_file_override_refuses_before_binding_or_profiles(setup, host, endpoint, tool, role):
    before = snapshot(setup.base)
    session = "12345678-1234-1234-1234-123456789abc"
    result = setup.add_role(endpoint, host, session=session, tools=tool, cwd=str(setup.source), expect=2)
    assert result == {"error": "the %s role does not permit file tool: %s" % (role, tool)}
    assert snapshot(setup.base) == before


@pytest.mark.parametrize("endpoint,role", [("pilot/lane/review", "reviewer"), ("pilot/decider", "decider")])
def test_forbidden_override_cannot_replace_an_existing_valid_profile(setup, endpoint, role):
    session = "12345678-1234-1234-1234-123456789abc"
    setup.add_role(endpoint, session=session, tools="Read", cwd=str(setup.source))
    before = snapshot(setup.base)
    result = setup.add_role(endpoint, session=session, tools="Read,Write", cwd=str(setup.source), expect=2)
    assert result == {"error": "the %s role does not permit file tool: Write" % role}
    assert snapshot(setup.base) == before


@pytest.mark.parametrize("endpoint,tools", [
    ("pilot/lane/f2", "Read,Write,Edit"), ("pilot/lane/integration", "Edit"),
    ("pilot/lane/review", "Read,Grep"), ("pilot/decider", "Read"),
])
def test_file_overrides_can_narrow_the_registry_tools(setup, endpoint, tools):
    role = setup.add_role(endpoint, tools=tools, cwd=str(setup.source))
    profile = json.loads(Path(role["wake_profile"]).read_text())
    assert "--tools=" + tools in profile["argv"]
    allowed = profile["argv"][profile["argv"].index("--allowedTools") + 1].split(",")
    assert set(allowed) & {"Write", "Edit"} == set(tools.split(",")) & {"Write", "Edit"}


def board_connection(setup, endpoint):
    invoke(setup.root, "bind", {"endpoint": endpoint, "host": "fixture", "session": endpoint,
                                "expected_generation": 0})
    board = setup.tmp / "board"
    initialized = subprocess.run([sys.executable, "-I", str(BOARD), "--board", str(board), "init"],
                                 capture_output=True, text=True, timeout=20)
    assert initialized.returncode == 0, initialized.stdout + initialized.stderr
    before = snapshot(setup.base), snapshot(board)
    response = subprocess.run([sys.executable, "-I", str(HELPER), "--root", str(setup.root), "serve", "--endpoint",
                               endpoint, "--host", "fixture", "--session", endpoint, "--generation", "1",
                               "--board", str(board)], capture_output=True, text=True, timeout=20,
                              input=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}) + "\n")
    assert (snapshot(setup.base), snapshot(board)) == before
    assert not response.stderr
    return response


@pytest.mark.parametrize("endpoint,role", [
    ("pilot/lane/review", "reviewer"), ("pilot/router", "router"), ("pilot/decider", "decider"),
])
def test_direct_mcp_board_connection_refuses_a_role_without_board_access(setup, endpoint, role):
    response = board_connection(setup, endpoint)
    assert response.returncode == 2, response.stdout
    assert json.loads(response.stdout) == {"error": "the %s role has no board access" % role}


@pytest.mark.parametrize("endpoint", ["pilot/lane/f2", "pilot/lane/integration", "pilot/orchestrator", "pilot/front-door"])
def test_direct_mcp_board_connection_preserves_permitted_roles(setup, endpoint):
    response = board_connection(setup, endpoint)
    assert response.returncode == 0, response.stdout
    assert {tool["name"] for tool in json.loads(response.stdout)["result"]["tools"]} == BOARD_TOOLS
