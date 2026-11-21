"""Moving a live initiative to a new mailbox root: the sessions stay, open work is carried, the old root is untouched.

The old root here is built the way the live ones are: native threads labelled codex, CLI lanes labelled
codex-cli, two hierarchies with a counterpart route, no reachable job flow. No host runs in these tests.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess

import pytest

from tests.integration.test_hierarchy_mailbox import invoke, mailbox_snapshot, readiness
from tests.integration.test_hierarchy_provision import INITIATIVE, Setup, provision


pytestmark = pytest.mark.skipif(os.name == "nt", reason="generated profiles are POSIX only")
SESSIONS = {"a/front-door": ("codex", "native-front-door"), "a/orchestrator": ("codex", "native-orchestrator"),
            "a/root": ("codex", "native-root"), "a/lane/build": ("codex-cli", "cli-build"), "a/lane/look": ("codex-cli", "cli-look"),
            "b/front-door": ("codex", "native-front-door-b"), "b/orchestrator": ("codex", "native-orchestrator-b"),
            "b/lane/other": ("codex-cli", "cli-other")}
LANES = {"build": "implementer", "fix": "integrator", "look": "reviewer"}
BODY = "UNTRUSTED-OLD-BODY"


class Move(Setup):
    def __init__(self, tmp_path):
        super().__init__(tmp_path)
        (tmp_path / "old").mkdir()
        self.old = tmp_path / "old" / "mailbox"
        endpoints = {"a/front-door": {}, "a/orchestrator": {}, "a/root": {}, "a/lane/build": {"kind": "implementer"},
                     "a/lane/fix": {"kind": "integrator"}, "a/lane/look": {"kind": "reviewer"}, "b/front-door": {},
                     "b/orchestrator": {}, "b/lane/other": {"kind": "implementer"}}
        invoke(self.old, "init", {"schema": "aegis.hierarchy-pilot/v1", "endpoints": endpoints, "writer_limit": 3,
                                  "counterparts": [["a/front-door", "b/front-door"]]})
        for endpoint, (host, session) in SESSIONS.items():
            invoke(self.old, "bind", {"endpoint": endpoint, "host": host, "session": session, "expected_generation": 0})
        self.base = tmp_path / "initiatives" / "a"
        provision("init", self.request(store=str(self.workspace.store), base=str(self.base), source=str(self.source), lanes=LANES,
                                       initiative={**INITIATIVE, "id": "a", "project": "aegis", "repository": "aegis"}))
        raw = b"Do the work.\n"
        self.brief_path = tmp_path / "old" / "brief.md"
        self.brief_path.write_bytes(raw)
        self.brief = {"path": str(self.brief_path), "sha256": hashlib.sha256(raw).hexdigest()}

    def send(self, root, sender, recipient, identifier, kind="info", body=BODY, **extra):
        binding = invoke(root, "status")["bindings"][sender]
        return invoke(root, "publish", {"message_id": identifier, "from": sender, "to": recipient, "host": binding["host"],
                                        "session": binding["session"], "binding_generation": binding["generation"], "type": kind,
                                        "body": body, **extra})

    def old_dispatch(self, identifier, lane):
        self.send(self.old, "a/orchestrator", lane, identifier, "dispatch", brief=self.brief)

    def old_accept(self, identifier, lane, ready=None):
        extra = {"readiness": ready} if ready else {}
        self.send(self.old, lane, "a/orchestrator", identifier + "-accepted", "ack", in_reply_to=identifier, acknowledgment="accepted", **extra)

    def bind_new(self, *skip):
        roles = {}
        for endpoint, (host, session) in SESSIONS.items():
            if endpoint.startswith("a/") and endpoint not in skip:
                options = {"cwd": str(self.source)} if host == "codex-cli" else {}
                roles[endpoint] = self.add_role(endpoint, host, session=session, **options)
        return roles

    def carry(self, *, expect=0, **changes):
        body = {"base": str(self.base), "old_root": str(self.old), "hierarchy": "a", "note": "The owner approved this move.", **changes}
        return provision("carry", self.request(**body), expect=expect)

    def check(self, *, expect=0):
        return provision("carry-check", self.request(base=str(self.base)), expect=expect)

    def carried_message(self):
        page = invoke(self.root, "inbox", endpoint="a/orchestrator", include_briefs=True, limit=100)
        rows = [row for row in page["messages"] if row["message"]["type"] == "brief"]
        assert len(rows) == 1, page["messages"]
        return rows[0]

    def writers(self):
        return self.workspace.run("status")["capacity"]["writer"]


@pytest.fixture
def move(tmp_path):
    return Move(tmp_path)


def test_the_orchestrator_gets_a_hash_bound_record_of_open_work_and_the_old_root_stays_untouched(move, tmp_path):
    ready = readiness(tmp_path, "build-worktree", "feature/build")
    move.old_dispatch("build-1", "a/lane/build")
    move.old_accept("build-1", "a/lane/build", ready)
    move.old_dispatch("look-1", "a/lane/look")
    move.bind_new()
    before = mailbox_snapshot(move.old)
    result = move.carry()
    assert mailbox_snapshot(move.old) == before, "the old root is only read"
    assert {row["dispatch"]: row["accepted"] for row in result["open_dispatches"]} == {"build-1": True, "look-1": False}
    row = move.carried_message()
    message = row["message"]
    assert message["from"] == "a/root" and message["authority"] == "information_only"
    assert hashlib.sha256(Path(message["brief"]["path"]).read_bytes()).hexdigest() == message["brief"]["sha256"]
    text = row["brief_text"]
    for expected in ("build-1", "look-1", ready["worktree"], ready["branch"], ready["lease_ref"], str(move.old),
                     "The owner approved this move.", "native-orchestrator"):
        assert expected in text, expected
    assert BODY not in text, "old message bodies are untrusted, so they are pointed to and never copied"


def test_a_carried_brief_keeps_its_bytes_and_continues_the_work_in_the_new_root(move, tmp_path):
    ready = readiness(tmp_path, "build-worktree", "feature/build")
    move.old_dispatch("build-1", "a/lane/build")
    move.old_accept("build-1", "a/lane/build", ready)
    move.bind_new()
    carried = move.carry()["open_dispatches"][0]["brief"]
    assert carried["sha256"] == move.brief["sha256"] and carried["path"] != move.brief["path"]
    assert Path(carried["path"]).read_bytes() == move.brief_path.read_bytes()
    move.send(move.root, "a/orchestrator", "a/lane/build", "build-1-again", "dispatch", brief=carried)
    move.send(move.root, "a/lane/build", "a/orchestrator", "build-1-again-accepted", "ack", in_reply_to="build-1-again",
              acknowledgment="accepted", readiness=ready)
    assert [row["dispatch"] for row in invoke(move.root, "status")["accepted_writers"]] == ["build-1-again"]


def test_a_writer_already_at_work_takes_a_shared_slot_once_and_a_reviewer_takes_none(move, tmp_path):
    move.old_dispatch("build-1", "a/lane/build")
    move.old_accept("build-1", "a/lane/build", readiness(tmp_path, "build-worktree", "feature/build"))
    move.old_dispatch("look-1", "a/lane/look")
    move.old_accept("look-1", "a/lane/look")
    move.bind_new()
    move.carry()
    writers = move.writers()
    assert writers["used"] == 1 and writers["holders"][0]["holder"] == "a/lane/build" and writers["holders"][0]["state"] == "granted"
    move.carry()
    assert move.writers()["used"] == 1


def test_a_full_ledger_refuses_the_move_and_changes_nothing(move, tmp_path):
    for number in range(3):
        move.workspace.run("request", {"initiative": "a", "kind": "writer", "holder": "other-%d" % number})
        move.workspace.run("grant-next", kind="writer")
    move.old_dispatch("build-1", "a/lane/build")
    move.old_accept("build-1", "a/lane/build", readiness(tmp_path, "build-worktree", "feature/build"))
    move.bind_new()
    assert "no writer capacity" in move.carry(expect=2)["error"]
    assert not (move.base / "carried").exists()
    assert not [row for row in invoke(move.root, "inbox", endpoint="a/orchestrator")["messages"]]


def test_every_session_bound_in_the_old_root_must_be_bound_in_the_new_one(move):
    move.bind_new("a/lane/look")
    assert "a/lane/look" in move.carry(expect=2)["error"]


def test_an_endpoint_nobody_held_in_the_old_root_needs_no_binding(move):
    move.bind_new()
    assert move.carry()["open_dispatches"] == []


def test_a_different_session_is_refused_unless_named_as_a_replacement(move):
    move.bind_new("a/orchestrator")
    move.add_role("a/orchestrator", "codex", session="fresh-successor")
    assert "a/orchestrator" in move.carry(expect=2)["error"]
    result = move.carry(replaced={"a/orchestrator": "Rotated at the move."})
    assert result["replaced"] == ["a/orchestrator"]
    assert "Rotated at the move." in move.carried_message()["brief_text"]


@pytest.mark.parametrize("name", [".write.lock", ".wake-a%2Flane%2Fbuild.lock"])
def test_a_busy_old_root_refuses_the_move(move, name):
    move.bind_new()
    lock = move.old / name
    lock.write_text("fixture")
    assert "busy" in move.carry(expect=2)["error"]
    lock.unlink()
    assert move.carry()["open_dispatches"] == []


def test_the_new_initiative_must_be_the_old_hierarchy(move):
    move.bind_new()
    assert "hierarchy" in move.carry(hierarchy="b", expect=2)["error"]
    assert "hierarchy" in move.carry(hierarchy="none", expect=2)["error"]


def test_an_initiative_with_another_name_is_refused(tmp_path):
    move = Move(tmp_path)
    other = tmp_path / "initiatives" / "shrunk"
    provision("init", move.request(store=str(move.workspace.store), base=str(other), source=str(move.source), lanes={"look": "reviewer"},
                                   initiative={**INITIATIVE, "id": "shrunk", "project": "aegis", "repository": "aegis"}))
    move.base = other
    assert "hierarchy" in move.carry(expect=2)["error"]


def test_closed_dispatches_and_other_hierarchies_stay_out(move):
    move.old_dispatch("look-done", "a/lane/look")
    move.old_accept("look-done", "a/lane/look")
    move.send(move.old, "a/lane/look", "a/orchestrator", "look-done-verdict", "review", in_reply_to="look-done", result={
        "source_revision": "a" * 40, "source_tree": "b" * 40, "checks": [{"check": "read it", "outcome": "pass", "reference": "x"}]})
    move.send(move.old, "b/orchestrator", "b/lane/other", "b-work", "dispatch", brief=move.brief)
    move.bind_new()
    assert move.carry()["open_dispatches"] == []
    text = move.carried_message()["brief_text"]
    assert "b-work" not in text and "No open dispatches." in text


def test_an_open_job_request_is_listed_to_be_asked_again(move):
    held = move.send(move.old, "a/orchestrator", "a/root", "job-packet", "info")
    move.send(move.old, "a/orchestrator", "a/root", "job-1", "job_request", brief={"path": held["path"], "sha256": held["sha256"]})
    move.bind_new()
    assert move.carry()["open_job_requests"] == ["job-1"]
    assert "job-1" in move.carried_message()["brief_text"]


def test_a_move_interrupted_after_its_record_finishes_on_the_next_run_and_repeats_nothing(move, tmp_path):
    move.old_dispatch("build-1", "a/lane/build")
    move.old_accept("build-1", "a/lane/build", readiness(tmp_path, "build-worktree", "feature/build"))
    move.bind_new()
    lock = move.root / ".write.lock"
    lock.write_text("fixture")
    assert "busy" in move.carry(expect=2)["error"]
    assert move.writers()["used"] == 1
    lock.unlink()
    first = move.carry()
    assert move.writers()["used"] == 1
    assert move.carried_message()
    second = move.carry()
    assert second["brief"] == first["brief"]
    assert move.carried_message(), "still exactly one"


def test_a_bad_request_is_refused(move):
    move.bind_new()
    assert "note" in move.carry(note="", expect=2)["error"]
    assert "unexpected" in move.carry(extra="x", expect=2)["error"]


def test_the_check_reports_mail_that_reached_the_old_root_after_the_move(move):
    move.bind_new()
    move.carry()
    assert move.check() == {"clean": True, "late_messages": [], "changed_bindings": []}
    move.send(move.old, "b/orchestrator", "b/lane/other", "other-hierarchy")
    assert move.check()["clean"] is True, "another hierarchy's mail is not this initiative's"
    move.send(move.old, "a/front-door", "a/orchestrator", "late-mail")
    report = move.check(expect=3)
    assert report["clean"] is False
    assert [row["message_id"] for row in report["late_messages"]] == ["late-mail"]
    assert BODY not in json.dumps(report)


def test_the_check_reports_an_old_binding_that_changed_after_the_move(move):
    move.bind_new()
    move.carry()
    request = invoke(move.old, "draft-handoff", {"endpoint": "a/lane/look", "host": "codex-cli", "session": "late-rotation", "outgoing_stopped": True,
                                                 "briefs": [move.brief]})
    invoke(move.old, "bind", request)
    assert move.check(expect=3)["changed_bindings"] == ["a/lane/look"]


def test_the_check_needs_a_finished_move(move):
    assert "not been carried" in move.check(expect=2)["error"]


def adapter_call(connection, name, arguments):
    definition = json.loads(Path(connection).read_text())
    frame = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": arguments}}
    done = subprocess.run([definition["command"], *definition["args"]], input=json.dumps(frame) + "\n", capture_output=True, text=True, timeout=20,
                          env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert done.returncode == 0, done.stdout + done.stderr
    return json.loads(json.loads(done.stdout)["result"]["content"][0]["text"])


def test_a_native_session_reads_the_carried_work_through_its_new_connection_with_a_receipt(move):
    roles = move.bind_new()
    move.carry()
    page = adapter_call(roles["a/orchestrator"]["connection"], "mailbox_inbox", {"include_briefs": True})
    assert page["messages"][0]["message"]["type"] == "brief"
    identifier = page["messages"][0]["message"]["message_id"]
    state = invoke(move.root, "delivery", delivery_dir=str(move.base / "delivery"), message_id=identifier)["message"]
    assert state["state"] == "read" and state["read_by"] == {"host": "codex", "session": "native-orchestrator", "generation": 1}


def test_one_native_session_can_hold_endpoints_in_two_new_roots(move):
    first = move.add_role("a/front-door", "codex", session="native-front-door")
    other = move.tmp / "initiatives" / "c"
    provision("init", move.request(store=str(move.workspace.store), base=str(other), source=str(move.source), lanes=LANES,
                                   initiative={**INITIATIVE, "id": "c", "project": "aegis", "repository": "aegis"}))
    second = provision("add-role", move.request(base=str(other), endpoint="c/front-door", host="codex", session="native-front-door"))
    assert first["connection"] != second["connection"]
    assert adapter_call(first["connection"], "mailbox_inbox", {})["endpoint"] == "a/front-door"
    assert adapter_call(second["connection"], "mailbox_inbox", {})["endpoint"] == "c/front-door"


def test_a_move_that_stopped_before_its_record_starts_over_cleanly(move, tmp_path):
    move.old_dispatch("build-1", "a/lane/build")
    move.old_accept("build-1", "a/lane/build", readiness(tmp_path, "build-worktree", "feature/build"))
    move.bind_new()
    first = move.carry()
    (move.base / "carried" / "carry.json").unlink()
    second = move.carry()
    assert second["brief"]["sha256"] == first["brief"]["sha256"]
    assert move.carried_message(), "still exactly one"
    assert move.writers()["used"] == 1


def test_a_damaged_store_does_not_stop_a_sessions_mailbox(move):
    roles = move.bind_new()
    move.carry()
    (move.workspace.store / "events" / "00000001.json").write_text("{damaged")
    connection = roles["a/orchestrator"]["connection"]
    assert adapter_call(connection, "mailbox_inbox", {})["endpoint"] == "a/orchestrator"
    definition = json.loads(Path(connection).read_text())
    frame = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "workspace_capacity", "arguments": {}}}
    done = subprocess.run([definition["command"], *definition["args"]], input=json.dumps(frame) + "\n", capture_output=True, text=True, timeout=20,
                          env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    answer = json.loads(done.stdout)["result"]
    assert answer["isError"] is True and "malformed workspace event" in answer["content"][0]["text"]


UUID_A = "01a19a9d-b1ad-7b22-bec1-5e465d490ae6"
UUID_B = "01a19a8e-3073-7af2-b5c0-d0c41fe82ada"


def move_request(move, **changes):
    body = {"store": str(move.workspace.store), "base": str(move.tmp / "initiatives" / "moved" / "a"), "source": str(move.source), "old_root": str(move.old),
            "hierarchy": "a", "note": "The owner approved this move.", "root": {"host": "codex", "session": UUID_B},
            "initiative": {"project": "aegis", "repository": "aegis", "priority": 5, "target_branch": "develop", "source": "owner"}, **changes}
    return move.request(**body)


@pytest.fixture
def fresh(tmp_path):
    """The old root only, because `move` makes the new initiative itself."""
    built = Move.__new__(Move)
    Setup.__init__(built, tmp_path)
    (tmp_path / "old").mkdir()
    built.old = tmp_path / "old" / "mailbox"
    endpoints = {"a/front-door": {}, "a/orchestrator": {}, "a/lane/build": {"kind": "implementer"}, "a/lane/fix": {"kind": "integrator"},
                 "a/lane/look": {"kind": "reviewer"}, "b/front-door": {}, "b/orchestrator": {}}
    invoke(built.old, "init", {"schema": "aegis.hierarchy-pilot/v1", "endpoints": endpoints, "writer_limit": 3, "counterparts": [["a/front-door", "b/front-door"]]})
    for endpoint, host, session in (("a/front-door", "codex", "native-front-door"), ("a/orchestrator", "codex", "native-orchestrator"),
                                    ("a/lane/build", "codex-cli", "cli-build"), ("a/lane/look", "codex-cli", "cli-look"), ("b/front-door", "codex", "other")):
        invoke(built.old, "bind", {"endpoint": endpoint, "host": host, "session": session, "expected_generation": 0})
    raw = b"Do the work.\n"
    built.brief_path = tmp_path / "old" / "brief.md"
    built.brief_path.write_bytes(raw)
    built.brief = {"path": str(built.brief_path), "sha256": hashlib.sha256(raw).hexdigest()}
    return built


def test_one_command_moves_a_hierarchy_keeping_every_session(fresh):
    before = mailbox_snapshot(fresh.old)
    result = provision("move", move_request(fresh, roles={"a/lane/look": {"cwd": str(fresh.source), "reader_shell": True}}))
    assert mailbox_snapshot(fresh.old) == before
    roles = result["roles"]
    assert sorted(roles) == ["a/front-door", "a/lane/build", "a/lane/look", "a/orchestrator", "a/root"]
    assert roles["a/orchestrator"]["session"] == "native-orchestrator" and roles["a/orchestrator"]["wake"] == "native"
    assert roles["a/root"]["session"] == UUID_B
    assert "wake_profile" in roles["a/lane/look"]
    assert result["needs_profile"] == ["a/lane/build"], "an idle CLI lane is bound, and gets its profile when it has a worktree"
    assert roles["a/orchestrator"]["connection"] in result["tell"]["a/orchestrator"] and str(fresh.old) in result["tell"]["a/orchestrator"]
    assert "a/lane/build" not in result["tell"]
    assert result["carry"]["open_dispatches"] == []
    root = Path(result["mailbox_root"])
    assert invoke(root, "status")["bindings"]["a/lane/fix"] is None
    assert adapter_call(roles["a/orchestrator"]["connection"], "mailbox_inbox", {})["messages"][0]["message"]["type"] == "brief"


def test_moving_again_repeats_nothing(fresh):
    first = provision("move", move_request(fresh))
    second = provision("move", move_request(fresh))
    assert second["carry"]["brief"] == first["carry"]["brief"]
    assert second["roles"]["a/orchestrator"]["connection"] == first["roles"]["a/orchestrator"]["connection"]
    page = invoke(Path(first["mailbox_root"]), "inbox", endpoint="a/orchestrator", limit=100)
    assert len(page["messages"]) == 1


def test_a_role_can_move_to_a_named_replacement_with_a_real_session(fresh):
    replaced = {"a/orchestrator": {"host": "codex", "session": UUID_A, "reason": "Root keeps its hold on the old session."}}
    result = provision("move", move_request(fresh, replaced=replaced))
    assert result["roles"]["a/orchestrator"]["session"] == UUID_A
    assert result["carry"]["replaced"] == ["a/orchestrator"]
    placeholder = {"a/orchestrator": {"host": "codex", "session": "REPLACE_WITH_THE_ACTUAL_THREAD_ID", "reason": "x"}}
    other = move_request(fresh, replaced=placeholder, base=str(fresh.tmp / "initiatives" / "moved" / "second"))
    assert "actual" in provision("move", other, expect=2)["error"]


@pytest.mark.parametrize("changes, reason", [
    ({"hierarchy": "none"}, "no such hierarchy"),
    ({"roles": {"a/lane/nope": {"cwd": "/tmp"}}}, "a/lane/nope"),
    ({"replaced": {"a/lane/nope": {"host": "codex", "session": UUID_A, "reason": "x"}}}, "a/lane/nope"),
    ({"root": {"host": "codex"}}, "missing fields"),
    ({"initiative": {"project": "aegis"}}, "missing fields"),
    ({"root": {"host": "codex", "session": "REPLACE_WITH_THE_ACTIVE_ROOT"}}, "actual"),
    ({"surprise": 1}, "unexpected"),
])
def test_a_bad_move_request_is_refused_and_binds_nothing(fresh, changes, reason):
    request = move_request(fresh, **changes)
    assert reason in provision("move", request, expect=2)["error"]
    assert not (fresh.tmp / "initiatives" / "moved").exists()


def test_a_writer_cannot_default_to_running_in_the_pinned_tools_checkout(fresh):
    result = provision("move", move_request(fresh, roles={"a/lane/look": {"reader_shell": True, "cwd": str(fresh.source)}}))
    assert "a/lane/build" in result["needs_profile"]
    profiles = Path(result["mailbox_root"]).parent / "profiles"
    assert not list(profiles.glob("a%2Flane%2Fbuild*"))


def test_a_writer_already_queued_is_granted_by_the_move(move, tmp_path):
    """Capacity counts only granted requests, so a queued one left by an earlier attempt must not pass for a held slot."""
    move.old_dispatch("build-1", "a/lane/build")
    move.old_accept("build-1", "a/lane/build", readiness(tmp_path, "build-worktree", "feature/build"))
    move.bind_new()
    move.workspace.run("request", {"initiative": "a", "kind": "writer", "holder": "a/lane/build"})
    move.carry()
    writers = move.writers()
    assert writers["used"] == 1 and writers["holders"][0]["holder"] == "a/lane/build"
    assert [row for row in move.workspace.run("status")["capacity"]["queue"] if row["holder"] == "a/lane/build"] == []


def test_a_queued_writer_with_no_room_refuses_the_move(move, tmp_path):
    for number in range(3):
        move.workspace.run("request", {"initiative": "a", "kind": "writer", "holder": "other-%d" % number})
        move.workspace.run("grant-next", kind="writer")
    move.old_dispatch("build-1", "a/lane/build")
    move.old_accept("build-1", "a/lane/build", readiness(tmp_path, "build-worktree", "feature/build"))
    move.bind_new()
    move.workspace.run("request", {"initiative": "a", "kind": "writer", "holder": "a/lane/build"})
    assert "no writer capacity" in move.carry(expect=2)["error"]
    assert not (move.base / "carried").exists()


def test_a_busy_store_stops_a_move_before_it_creates_anything(fresh):
    lock = fresh.workspace.store / ".write.lock"
    lock.write_text("fixture")
    assert "busy" in provision("move", move_request(fresh), expect=2)["error"]
    assert not (fresh.tmp / "initiatives" / "moved" / "a").exists()
    lock.unlink()
    provision("move", move_request(fresh))
    assert "a" in fresh.workspace.run("status")["initiatives"]


@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root ignores file modes")
def test_a_registration_that_failed_after_setup_is_finished_by_the_next_move(fresh):
    events = fresh.workspace.store / "events"
    base = fresh.tmp / "initiatives" / "moved" / "a"
    events.chmod(0o500)
    try:
        provision("move", move_request(fresh), expect=2)
    finally:
        events.chmod(0o700)
    assert (base / "provision.json").exists() and "a" not in fresh.workspace.run("status")["initiatives"]
    refused = provision("carry", fresh.request(base=str(base), old_root=str(fresh.old), hierarchy="a", note="Retry."), expect=2)
    assert "not registered" in refused["error"]
    provision("move", move_request(fresh))
    assert "a" in fresh.workspace.run("status")["initiatives"]
    assert "a" in [row["id"] for row in fresh.workspace.run("report")["initiatives"]]

