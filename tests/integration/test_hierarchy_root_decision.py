"""ROOT's decision adapter: approve or deny an existing canonical request, and read the team without changing it.

The ROOT actor is configuration, not an authenticated identity. These tests show what the adapter
records and refuses; they make no claim about what a real host lets a ROOT session do.
"""
import ast
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
import subprocess
import sys
import threading

import pytest

from tests.integration.test_hierarchy_lifecycle import Ledger, raw_request, request
from tests.integration.test_hierarchy_mailbox import HELPER, invoke, mailbox_snapshot
from tests.integration.test_hierarchy_mailbox_mcp import payload
from tests.integration.test_hierarchy_root_role import ENDPOINTS


sys.path.insert(0, str(HELPER.parent))
import hierarchy_lifecycle  # noqa: E402
import hierarchy_roles  # noqa: E402


pytestmark = pytest.mark.skipif(os.name != "posix", reason="durable lifecycle mutation requires POSIX directory fsync")
TOOL = "root_decide"
READ_TOOLS = ["team_status", "team_pending", "team_request"]
# ROOT's own entry: the pinned mailbox CLI cannot carry the read-only --loop-state and --evidence options.
ADAPTER = HELPER.parent / "hierarchy_mailbox_mcp.py"
TEAM_VIEW = HELPER.parent / "hierarchy_team_view.py"
ROOT_ENTRY_ONLY = ("hierarchy_mailbox_mcp.py serves only ROOT's decision adapter; "
                   "other roles launch through hierarchy_mailbox.py serve")


@pytest.fixture
def loop(tmp_path):
    root = tmp_path / "mailbox"
    invoke(root, "init", {"schema": "aegis.hierarchy-pilot/v1", "endpoints": ENDPOINTS, "counterparts": [],
                          "writer_limit": 3})
    for endpoint in ENDPOINTS:
        invoke(root, "bind", {"endpoint": endpoint, "host": "host-one", "session": endpoint, "expected_generation": 0})
    ledger = Ledger(tmp_path)
    value = request("feature-1")
    ledger.publish(value)
    return root, ledger, value


def rebind(root, host):
    brief = root.parent / "root-handoff.md"
    brief.write_bytes(b"ROOT handoff.\n")
    checkpoint = {"outgoing_stopped": True, "sources": [], "lease_refs": [], "completed_checks": [],
                  "pending_message_ids": [], "last_acknowledgment_ids": [],
                  "briefs": [{"path": str(brief), "sha256": hashlib.sha256(brief.read_bytes()).hexdigest()}]}
    return invoke(root, "bind", {"endpoint": "a/root", "host": host, "session": "root-2", "expected_generation": 1,
                                 "checkpoint": checkpoint})


def serve(root, ledger, calls=(), *, endpoint="a/root", actor="root-1", session=None, generation=1, extra=(),
          lifecycle=True, helper=HELPER):
    frames = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
              {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}]
    frames += [{"jsonrpc": "2.0", "id": index + 3, "method": "tools/call", "params": {"name": name, "arguments": arguments}}
               for index, (name, arguments) in enumerate(calls)]
    options = ["--lifecycle", str(ledger.path), "--actor", actor] if lifecycle else []
    return subprocess.run([sys.executable, "-I", str(helper), "--root", str(root), "serve", "--endpoint", endpoint,
                           "--host", "host-one", "--session", session or endpoint, "--generation", str(generation),
                           *options, *extra],
                          input="".join(json.dumps(frame) + "\n" for frame in frames), capture_output=True, text=True,
                          timeout=20, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})


def responses(result):
    assert result.returncode == 0, result.stdout + result.stderr
    assert not result.stderr
    return [json.loads(line) for line in result.stdout.splitlines()]


def decision(value, event_id="root-decision-1", verdict="approve", reason="the owner agreed this feature"):
    return {"event_id": event_id, "request_id": value["id"], "request_sha256": raw_request(value)["sha256"],
            "decision": verdict, "reason": reason}


def decisions(ledger):
    return [(d["request_id"], d["decision"], d["actor"]) for d in ledger.status()["decisions"]]


def test_root_is_offered_the_decision_tool_and_the_registry_read_tools_and_told_it_is_not_authenticated(loop):
    root, ledger, _ = loop
    for helper in (HELPER, ADAPTER):
        opened, listed = responses(serve(root, ledger, helper=helper))
        assert "not authenticated" in opened["result"]["instructions"]
        tools = {tool["name"]: tool for tool in listed["result"]["tools"]}
        assert [tool["name"] for tool in listed["result"]["tools"]] == [TOOL] + READ_TOOLS
        assert list(tools) == [TOOL] + list(hierarchy_roles.decision_tools(hierarchy_roles.registry()["roles"]["root"]))
        schema = tools[TOOL]["inputSchema"]
        assert set(schema["properties"]) == {"event_id", "request_id", "request_sha256", "decision", "reason"}
        assert schema["properties"]["decision"]["enum"] == ["approve", "deny"]
        assert schema["additionalProperties"] is False and tools[TOOL]["annotations"]["readOnlyHint"] is False
        assert [tools[name]["annotations"]["readOnlyHint"] for name in READ_TOOLS] == [True, True, True]
        assert all(tools[name]["inputSchema"]["additionalProperties"] is False for name in READ_TOOLS)
        assert tools["team_status"]["inputSchema"]["properties"] == tools["team_pending"]["inputSchema"]["properties"] == {}


def lifecycle_request_fields():
    """The request fields the lifecycle itself requires, read from its own refusal of an empty request."""
    raw = "{}"
    with pytest.raises(ValueError) as caught:
        hierarchy_lifecycle.validate_request({"raw": raw, "sha256": hashlib.sha256(raw.encode()).hexdigest()})
    return set(str(caught.value).removeprefix("missing fields: ").split(", "))


def test_team_request_takes_exactly_the_lifecycle_request_fields_without_the_schema(loop):
    root, ledger, _ = loop
    tools = {tool["name"]: tool for tool in responses(serve(root, ledger))[1]["result"]["tools"]}
    schema = tools["team_request"]["inputSchema"]
    assert set(schema["properties"]) == set(schema["required"]) == lifecycle_request_fields() - {"schema"}


def test_root_reads_what_it_owes_and_decides_it_with_the_arguments_it_was_given(loop):
    root, ledger, value = loop
    before, mail = ledger.files(), mailbox_snapshot(root)
    answer = payload(responses(serve(root, ledger, [("team_pending", {})]))[-1])
    assert ledger.files() == before and mailbox_snapshot(root) == mail
    assert answer["schema"] == "aegis.team-pending/v1"
    [row] = answer["pending"]
    sha = raw_request(value)["sha256"]
    assert (row["request_id"], row["request_sha256"], row["why"]) == ("feature-1", sha, "awaiting_decision")
    given = row["root_decide"]
    assert given == {"request_id": "feature-1", "request_sha256": sha, "event_id_approve": "root-feature-1-approve",
                     "event_id_deny": "root-feature-1-deny"}
    responses(serve(root, ledger, [(TOOL, {"event_id": given["event_id_approve"], "request_id": given["request_id"],
                                           "request_sha256": given["request_sha256"], "decision": "approve",
                                           "reason": "the owner agreed this feature"})]))
    assert decisions(ledger) == [("feature-1", "approve", "root-1")]
    assert payload(responses(serve(root, ledger, [("team_pending", {})]))[-1])["pending"] == []


def test_root_reads_the_team_status_from_the_journal_alone_when_given_no_loop_or_evidence(loop):
    root, ledger, _ = loop
    ledger.publish(request("feature-2"))
    ledger.approve(request("feature-2"))
    before = ledger.files()
    answer = payload(responses(serve(root, ledger, [("team_status", {})]))[-1])
    assert ledger.files() == before
    assert answer["schema"] == "aegis.team-status/v1"
    assert (answer["loop"], answer["evidence"]) == (None, None)
    assert answer["holds_by_act"] == {"root": [], "owner": [], "router": []}
    assert answer["pending"] == ["feature-1"]
    assert [{k: row[k] for k in ("request_id", "state")} for row in answer["requests"]] == [{"request_id": "feature-1", "state": "awaiting_decision"},
                                  {"request_id": "feature-2", "state": "approved"}]


def loop_status(folder, finished):
    folder.mkdir()
    row = {"step": "sweep", "kind": "root_queue", "detail": "mail for ROOT", "act": "root", "endpoint": "a/root",
           "first_seen": finished, "last_seen": finished, "count": 3}
    (folder / "status.json").write_text(json.dumps({
        "schema": "aegis.loop-status/v1", "pass_id": 4, "started_at": finished, "finished_at": finished, "interval": 30,
        "steps": [], "holds": [row], "stopped": False, "consecutive_journal_unavailable": 0}))
    return row


def test_root_reads_the_loop_and_evidence_its_entry_was_given_and_changes_neither(loop, tmp_path):
    root, ledger, _ = loop
    hour_ago = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    state_dir, evidence = tmp_path / "loop", tmp_path / "evidence"
    row = loop_status(state_dir, hour_ago)
    evidence.mkdir()
    (evidence / "init.json").write_text("{}")
    folders = {path: path.read_bytes() for folder in (state_dir, evidence) for path in folder.rglob("*")}
    answer = payload(responses(serve(root, ledger, [("team_status", {})], helper=ADAPTER,
                                     extra=["--loop-state", str(state_dir), "--evidence", str(evidence)]))[-1])
    assert answer["loop"]["state"] == "stale" and answer["loop"]["pass_id"] == 4
    assert answer["holds_by_act"] == {"root": [row], "owner": [], "router": []}
    assert answer["evidence"] == {"directory": str(evidence), "present": True, "files": 1, "sha256sums": None,
                                  "listed": None}
    assert {path: path.read_bytes() for folder in (state_dir, evidence) for path in folder.rglob("*")} == folders


def test_a_malformed_loop_status_is_a_refusal_for_that_call_only(loop, tmp_path):
    root, ledger, _ = loop
    state_dir = tmp_path / "loop"
    state_dir.mkdir()
    (state_dir / "status.json").write_text(json.dumps({"schema": "aegis.loop-status/v1", "pass_id": -1}))
    refused, pending = responses(serve(root, ledger, [("team_status", {}), ("team_pending", {})], helper=ADAPTER,
                                       extra=["--loop-state", str(state_dir)]))[2:]
    assert refused["result"]["isError"] is True
    assert payload(refused)["error"] == "status file has a bad pass_id: " + str(state_dir / "status.json")
    assert [row["request_id"] for row in payload(pending)["pending"]] == ["feature-1"]


@pytest.mark.parametrize("name,arguments,error", [
    ("team_status", {"loop_state": "/elsewhere"}, "unexpected fields: loop_state"),
    ("team_pending", {"request_id": "feature-1"}, "unexpected fields: request_id"),
    ("team_request", {**{k: v for k, v in request("feature-2").items() if k != "schema"}, "paths": []},
     "invalid request paths"),
    ("team_request", {k: v for k, v in request("feature-2").items() if k not in ("schema", "owner")},
     "missing fields: owner"),
])
def test_read_tools_refuse_bad_arguments_and_write_nothing(loop, name, arguments, error):
    root, ledger, _ = loop
    before, mail = ledger.files(), mailbox_snapshot(root)
    refused = responses(serve(root, ledger, [(name, arguments)]))[-1]
    assert refused["result"]["isError"] is True
    assert payload(refused)["error"] == error
    assert ledger.files() == before and mailbox_snapshot(root) == mail


def test_root_drafts_a_request_for_the_coordinator_to_publish_and_nothing_is_written(loop, tmp_path):
    root, ledger, _ = loop
    fields = {key: value for key, value in request("feature-2").items() if key != "schema"}
    before, mail = ledger.files(), mailbox_snapshot(root)
    answer = payload(responses(serve(root, ledger, [("team_request", fields)]))[-1])
    assert ledger.files() == before and mailbox_snapshot(root) == mail
    assert answer["schema"] == "aegis.team-request/v1" and answer["published"] is False
    assert answer["event"]["id"] == "publish-feature-2" and answer["event"]["actor"] == "coordinator-1"
    assert answer["event"]["event"]["request"] == {"raw": answer["raw"], "sha256": answer["sha256"]}
    event = tmp_path / "draft.json"
    event.write_text(json.dumps(answer["event"]))
    ledger.cli("record", "--event", str(event), "--evidence-only")
    owed = payload(responses(serve(root, ledger, [("team_pending", {})]))[-1])["pending"]
    assert [(row["request_id"], row["request_sha256"]) for row in owed] == [
        ("feature-1", raw_request(request("feature-1"))["sha256"]), ("feature-2", answer["sha256"])]


def test_a_busy_journal_refuses_a_read_with_the_journals_own_lock_named(loop):
    root, ledger, _ = loop
    lock = ledger.path / ".write.lock"
    lock.write_text("{}")
    try:
        refused = responses(serve(root, ledger, [("team_pending", {})]))[-1]
    finally:
        lock.unlink()
    assert payload(refused)["error"] == ("lifecycle journal writer is busy; inspect an abandoned %s before retrying"
                                         % lock)


@pytest.mark.parametrize("verdict", ["approve", "deny"])
def test_root_records_a_decision_on_an_existing_request_under_its_configured_actor(loop, verdict):
    root, ledger, value = loop
    answer = payload(responses(serve(root, ledger, [(TOOL, decision(value, verdict=verdict))]))[-1])
    assert answer["identity"] == "configured" and answer["authenticated"] is False
    assert answer["execution_enabled"] is False and answer["receipt"]["execution_enabled"] is False
    assert answer["receipt"]["event_id"] == "root-decision-1"
    assert decisions(ledger) == [("feature-1", verdict, "root-1")]


def test_a_lost_reply_is_recovered_by_retrying_the_same_decision(loop):
    root, ledger, value = loop
    first = payload(responses(serve(root, ledger, [(TOOL, decision(value))]))[-1])
    before = ledger.files()
    again = payload(responses(serve(root, ledger, [(TOOL, decision(value))]))[-1])
    assert again["receipt"] == first["receipt"]
    assert ledger.files() == before


def test_a_reused_event_id_with_another_decision_is_refused(loop):
    root, ledger, value = loop
    responses(serve(root, ledger, [(TOOL, decision(value))]))
    before = ledger.files()
    refused = responses(serve(root, ledger, [(TOOL, decision(value, verdict="deny"))]))[-1]
    assert refused["result"]["isError"] is True
    assert payload(refused)["error"] == "event id conflicts with different bytes"
    assert ledger.files() == before


@pytest.mark.parametrize("change,error", [
    ({"request_id": "never-published"}, "unknown request id"),
    ({"request_sha256": "0" * 64}, "request sha256 mismatch"),
    ({"decision": "admit"}, "decision must be approve or deny"),
    ({"reason": ""}, "invalid decision reason"),
    ({"event_id": "../escape"}, "invalid event id"),
    ({"request_id": 7}, "invalid request id"),
    ({"request_sha256": None}, "invalid request sha256"),
    ({"decision": ["approve"]}, "decision must be approve or deny"),
    ({"reason": {"text": "x"}}, "invalid decision reason"),
    ({"reason": "x" * 1025}, "invalid decision reason"),
    ({"actor": "operator-1"}, "unexpected fields"),
    ({"custody": {"cid": "root-1", "generation": 1}}, "unexpected fields"),
])
def test_malformed_or_unknown_decisions_record_nothing(loop, change, error):
    root, ledger, value = loop
    before = ledger.files()
    refused = responses(serve(root, ledger, [(TOOL, {**decision(value), **change})]))[-1]
    assert refused["result"]["isError"] is True
    assert error in payload(refused)["error"]
    assert ledger.files() == before


@pytest.mark.parametrize("name,arguments", [
    ("mailbox_publish", {"message_id": "go", "to": "a/orchestrator", "type": "info", "body": "Run it."}),
    ("mailbox_inbox", {}),
    ("workspace_capacity", {}),
    ("board_publish", {}),
    ("mailbox_self", {}),
    ("router_status", {}),
    ("decider_record", {}),
    ("team_publish", {}),
    ("TEAM_STATUS", {}),
])
def test_root_attempts_to_reach_mail_or_execution_tools_are_refused(loop, name, arguments):
    root, ledger, _ = loop
    before = ledger.files()
    refused = responses(serve(root, ledger, [(name, arguments)]))[-1]
    assert refused["result"]["isError"] is True
    assert payload(refused)["error"] == "unknown ROOT tool: %s; ROOT only records decisions" % name
    assert ledger.files() == before
    assert invoke(root, "inbox", endpoint="a/orchestrator")["messages"] == []


def test_a_replaced_root_session_is_refused_before_anything_is_recorded(loop):
    root, ledger, value = loop
    rebind(root, "host-two")
    before = ledger.files()
    stale = serve(root, ledger, [(TOOL, decision(value))])
    assert stale.returncode == 2
    assert json.loads(stale.stdout)["error"] == "stale or mismatched sender binding"
    assert ledger.files() == before


def test_a_successor_that_has_not_acknowledged_its_handoff_cannot_decide(loop):
    root, ledger, value = loop
    rebind(root, "host-one")
    before = ledger.files()
    waiting = serve(root, ledger, [(TOOL, decision(value))], session="root-2", generation=2)
    assert waiting.returncode == 2
    assert json.loads(waiting.stdout)["error"] == "handoff checkpoint has not been acknowledged"
    assert ledger.files() == before


def test_a_root_actor_fenced_by_succession_is_refused(loop):
    root, ledger, value = loop
    checkpoint = ledger.cli("checkpoint")
    ledger.event("succeed", actor="root-2", predecessor="root-1", checkpoint_sha256=checkpoint["sha256"])
    before = ledger.files()
    refused = responses(serve(root, ledger, [(TOOL, decision(value))]))[-1]
    assert refused["result"]["isError"] is True
    assert payload(refused)["error"] == "stale ROOT custody"
    assert ledger.files() == before


@pytest.mark.parametrize("actor,error", [
    ("router-1", "actor router-1 is not a ROOT actor in the lifecycle policy"),
    ("nobody-1", "actor nobody-1 is not a ROOT actor in the lifecycle policy"),
    ("../x", "invalid actor"),
])
def test_only_a_configured_root_actor_starts(loop, actor, error):
    root, ledger, _ = loop
    result = serve(root, ledger, actor=actor)
    assert result.returncode == 2
    assert json.loads(result.stdout)["error"] == error


def test_root_without_a_lifecycle_journal_gets_no_adapter(loop):
    root, ledger, _ = loop
    result = serve(root, ledger, lifecycle=False)
    assert result.returncode == 2
    assert json.loads(result.stdout)["error"] == ("ROOT takes only the decision adapter: give --lifecycle and --actor; "
                                                  "operational controller access is forbidden")


@pytest.mark.parametrize("helper", [HELPER, ADAPTER])
@pytest.mark.parametrize("flag", ["--delivery-dir", "--workspace-store", "--board"])
def test_root_takes_no_mailbox_workspace_or_board_options(loop, tmp_path, flag, helper):
    root, ledger, _ = loop
    result = serve(root, ledger, extra=[flag, str(tmp_path)], helper=helper)
    assert result.returncode == 2
    assert json.loads(result.stdout)["error"] == "the ROOT decision adapter takes no mailbox, workspace or board options"


def test_roots_entry_takes_no_source_views_either(loop, tmp_path):
    root, ledger, _ = loop
    result = serve(root, ledger, extra=["--source-repo", str(tmp_path)], helper=ADAPTER)
    assert result.returncode == 2
    assert json.loads(result.stdout)["error"] == "the ROOT decision adapter takes no source views"


@pytest.mark.parametrize("flag", ["--loop-state", "--evidence"])
def test_roots_read_paths_must_be_absolute(loop, flag):
    root, ledger, _ = loop
    result = serve(root, ledger, extra=[flag, "relative/folder"], helper=ADAPTER)
    assert result.returncode == 2
    assert json.loads(result.stdout)["error"] == flag + " must be absolute without traversal: got 'relative/folder'"


def test_roots_entry_without_a_journal_gets_no_adapter(loop, tmp_path):
    root, ledger, _ = loop
    result = serve(root, ledger, lifecycle=False, extra=["--loop-state", str(tmp_path)], helper=ADAPTER)
    assert result.returncode == 2
    assert json.loads(result.stdout)["error"] == ("ROOT takes only the decision adapter: give --lifecycle and --actor; "
                                                  "operational controller access is forbidden")


@pytest.mark.parametrize("endpoint", ["a/orchestrator", "a/lane/f2", "a/lane/review", "a/front-door"])
def test_roots_entry_serves_no_other_role(loop, tmp_path, endpoint):
    root, ledger, _ = loop
    result = serve(root, ledger, endpoint=endpoint, lifecycle=False, extra=["--loop-state", str(tmp_path)],
                   helper=ADAPTER)
    assert result.returncode == 2
    assert json.loads(result.stdout)["error"] == ROOT_ENTRY_ONLY


def test_serve_gives_the_loop_state_and_evidence_to_root_alone(loop, tmp_path):
    import hierarchy_mailbox_mcp
    root, _ledger, _ = loop
    for option in ("loop_state", "evidence"):
        with pytest.raises(ValueError) as caught:
            hierarchy_mailbox_mcp.serve(root, "a/orchestrator", "host-one", "a/orchestrator", 1, **{option: tmp_path})
        assert str(caught.value) == "--loop-state and --evidence are only for ROOT's decision adapter"


# The read path is checked in its source, since a host runs it inside ROOT's session: nothing in it may start a
# process, reach the launcher or the job tool, or open a file for writing.
RUNS = {"subprocess", "hierarchy_launcher", "hierarchy_jobs", "hierarchy_wake", "multiprocessing", "pty"}
WRITES = {"write_text", "write_bytes", "mkdir", "makedirs", "unlink", "remove", "rename", "replace", "rmdir", "touch",
          "symlink_to", "chmod", "truncate", "writer_lock", "waiting_writer_lock", "record", "publish", "publish_file",
          "system", "popen", "fork", "execv", "spawnv"}


def imported(tree):
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom):
            names.add((node.module or "").split(".")[0])
    return names


def written(tree):
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", None)
        owner = getattr(getattr(node.func, "value", None), "id", None)
        if name in WRITES or (owner == "os" and name == "open"):
            found.append(name)
        elif name == "open":
            # open(path, mode) or path.open(mode)
            position = 0 if isinstance(node.func, ast.Attribute) else 1
            mode = node.args[position] if len(node.args) > position else next(
                (keyword.value for keyword in node.keywords if keyword.arg == "mode"), None)
            if mode is not None and not (isinstance(mode, ast.Constant) and set(mode.value) <= {"r", "b", "t"}):
                found.append("open for writing")
    return found


def test_the_root_read_path_starts_nothing_and_opens_nothing_for_writing():
    adapter = ast.parse(ADAPTER.read_text(encoding="utf-8"))
    view = ast.parse(TEAM_VIEW.read_text(encoding="utf-8"))
    [connection] = [node for node in adapter.body if isinstance(node, ast.ClassDef) and node.name == "DecisionConnection"]
    entries = [node for node in adapter.body if isinstance(node, ast.FunctionDef) and node.name in {"serve", "main"}]
    module_imports = [node for node in adapter.body if isinstance(node, (ast.Import, ast.ImportFrom))]
    assert len(entries) == 2
    for tree in (connection, view, *entries, *module_imports):
        assert not imported(tree) & RUNS
    readers = [node for node in connection.body if isinstance(node, ast.FunctionDef) and node.name in READ_TOOLS]
    assert sorted(node.name for node in readers) == sorted(READ_TOOLS)
    for tree in (view, *readers):
        assert written(tree) == []
    # The tool table is explicit: no name is looked up as an attribute, so no other method can be reached.
    assert "getattr" not in {getattr(node.func, "id", None) for node in ast.walk(connection) if isinstance(node, ast.Call)}


@pytest.mark.parametrize("endpoint, role", [("a/orchestrator", "orchestrator"), ("a/front-door", "front-door"),
                                            ("a/lane/f2", "implementer"), ("a/lane/review", "reviewer")])
def test_no_other_role_gets_the_decision_adapter(loop, endpoint, role):
    root, ledger, value = loop
    result = serve(root, ledger, endpoint=endpoint)
    assert result.returncode == 2
    assert json.loads(result.stdout)["error"] == "the %s role has no lifecycle connection" % role
    assert decisions(ledger) == []


def test_the_decision_is_what_lets_the_operator_admit_the_request(loop):
    root, ledger, value = loop
    assert "no approved bounded authority" in ledger.status()["continuation_holds"]["feature-1"]
    responses(serve(root, ledger, [(TOOL, decision(value))]))
    assert ledger.status()["continuation_candidates"] == ["feature-1"]
    ledger.admit(value)


def test_an_acknowledged_root_successor_decides_under_its_own_binding(loop):
    root, ledger, value = loop
    replacement = rebind(root, "host-one")
    invoke(root, "ack-handoff", {"endpoint": "a/root", "session": "root-2", "generation": 2,
                                 "checkpoint_sha256": replacement["checkpoint_sha256"]})
    answer = payload(responses(serve(root, ledger, [(TOOL, decision(value))], session="root-2", generation=2))[-1])
    assert answer["receipt"]["event_id"] == "root-decision-1"
    assert decisions(ledger) == [("feature-1", "approve", "root-1")]


class Live:
    """A running adapter, so the fence is checked on a call after startup, not only at startup."""

    def __init__(self, root, ledger):
        self.process = subprocess.Popen(
            [sys.executable, "-I", str(HELPER), "--root", str(root), "serve", "--endpoint", "a/root", "--host",
             "host-one", "--session", "a/root", "--generation", "1", "--lifecycle", str(ledger.path), "--actor",
             "root-1"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
        self.next = 0

    def ask(self, method, params=None):
        self.next += 1
        frame = {"jsonrpc": "2.0", "id": self.next, "method": method, "params": params or {}}
        self.process.stdin.write(json.dumps(frame) + chr(10))
        self.process.stdin.flush()
        return json.loads(self.process.stdout.readline())

    def close(self):
        self.process.stdin.close()
        assert self.process.wait(timeout=10) == 0
        assert self.process.stderr.read() == ""


@pytest.fixture
def live(loop):
    root, ledger, value = loop
    adapter = Live(root, ledger)
    assert "not authenticated" in adapter.ask("initialize")["result"]["instructions"]
    yield root, ledger, value, adapter
    adapter.close()


def test_a_root_replaced_while_its_adapter_runs_is_refused_on_its_next_call(live):
    root, ledger, value, adapter = live
    rebind(root, "host-two")
    before = ledger.files()
    refused = adapter.ask("tools/call", {"name": TOOL, "arguments": decision(value)})
    assert refused["result"]["isError"] is True
    assert payload(refused)["error"] == "stale or mismatched sender binding"
    assert ledger.files() == before


@pytest.mark.parametrize("held", ["mailbox", "lifecycle"])
def test_a_held_lock_refuses_the_decision_and_records_nothing(live, held):
    root, ledger, value, adapter = live
    lock = (root if held == "mailbox" else ledger.path) / ".write.lock"
    expected = ("mailbox writer is busy; inspect an abandoned lock before retrying" if held == "mailbox" else
                "lifecycle journal writer is busy; inspect an abandoned %s before retrying" % lock)
    before = ledger.files()
    lock.write_text("{}")
    try:
        refused = adapter.ask("tools/call", {"name": TOOL, "arguments": decision(value)})
        assert payload(refused)["error"] == expected
    finally:
        lock.unlink()
    assert ledger.files() == before
    assert payload(adapter.ask("tools/call", {"name": TOOL, "arguments": decision(value)}))["receipt"]
    assert decisions(ledger) == [("feature-1", "approve", "root-1")]


def test_a_moment_of_journal_contention_is_waited_out(live):
    root, ledger, value, adapter = live
    lock = ledger.path / ".write.lock"
    lock.write_text("{}")
    release = threading.Timer(0.3, lock.unlink)
    release.start()
    try:
        answer = adapter.ask("tools/call", {"name": TOOL, "arguments": decision(value)})
    finally:
        release.join(timeout=5)
    assert payload(answer)["receipt"]["event_id"] == "root-decision-1"
    assert decisions(ledger) == [("feature-1", "approve", "root-1")]
