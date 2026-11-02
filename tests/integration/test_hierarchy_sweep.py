"""The sweep wakes sessions with unread mail across initiatives and reports what stayed unread.

Hosts are the fake host on PATH, which reads and replies through the real adapter. These tests show
the tools work together, not that real sessions behave this way.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import uuid

import pytest

from tests.integration.test_hierarchy_background import STUB
from tests.integration.test_hierarchy_delivery import HELPER
from tests.integration.test_hierarchy_mailbox import ROOT, invoke
from tests.integration.test_hierarchy_provision import INITIATIVE, LANES, Setup, provision


SWEEP = ROOT / "tools" / "hierarchy_sweep.py"
FAKE_HOST = Path(__file__).with_name("hierarchy_fake_host.py")
posix_only = pytest.mark.skipif(os.name == "nt", reason="the wake tool supports POSIX process groups only")
pytestmark = posix_only


class Fleet(Setup):
    def __init__(self, tmp_path):
        super().__init__(tmp_path)
        self.bin = tmp_path / "fake-bin"
        self.bin.mkdir()
        for name in ("claude", "codex"):
            path = self.bin / name
            path.write_text("#!" + sys.executable + "\n" + FAKE_HOST.read_text(encoding="utf-8"), encoding="utf-8")
            path.chmod(path.stat().st_mode | stat.S_IXUSR)
        self.log = tmp_path / "fake-host.log"
        self.plan_path = tmp_path / "fake-host-plan.json"
        self.claude_home = tmp_path / "claude-home"
        self.plan({})

    def plan(self, plan):
        self.plan_path.write_text(json.dumps(plan), encoding="utf-8")

    def add_role(self, endpoint, host="claude-code", *, expect=0, **changes):
        role = super().add_role(endpoint, host, expect=expect, **changes)
        if expect == 0:
            started(self, host, role["session"])
        return role

    def env(self):
        return {**os.environ, "PATH": str(self.bin) + os.pathsep + os.environ["PATH"], "PYTHONDONTWRITEBYTECODE": "1",
                "FAKE_HOST_LOG": str(self.log), "FAKE_HOST_PLAN": str(self.plan_path),
                "CLAUDE_CONFIG_DIR": str(self.claude_home), "CODEX_HOME": str(self.tmp / "codex-home")}

    def sweep(self, *flags, expect=0, store=None):
        result = subprocess.run([sys.executable, "-I", str(SWEEP), "--store", str(store or self.workspace.store), *flags],
                                capture_output=True, text=True, timeout=90, env=self.env())
        assert not result.stderr, result.stderr
        assert result.returncode == expect, result.stdout
        return json.loads(result.stdout)

    def launches(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def send(self, sender, recipient, identifier, *, root=None, **extra):
        root = root or self.root
        binding = invoke(root, "status")["bindings"][sender]
        return invoke(root, "publish", {"message_id": identifier, "from": sender, "to": recipient, "host": binding["host"],
                                        "session": binding["session"], "binding_generation": binding["generation"],
                                        "type": "info", "body": "UNTRUSTED-BODY", **extra})


def started(fleet, host, session):
    """A real session has a transcript from its first turn, which is how the meter finds its active time."""
    if host == "claude-code":
        folder = fleet.claude_home / "projects" / "-pilot"
        name = session + ".jsonl"
    elif host == "codex-cli":
        folder = fleet.tmp / "codex-home" / "sessions" / "2026"
        name = "rollout-2026-" + session + ".jsonl"
    else:
        return
    folder.mkdir(parents=True, exist_ok=True)
    if not (folder / name).exists():
        (folder / name).write_text("")


@pytest.fixture
def fleet(tmp_path):
    built = Fleet(tmp_path)
    built.init()
    built.front_door = built.add_role("pilot/front-door", cwd=str(tmp_path))
    built.orchestrator = built.add_role("pilot/orchestrator", cwd=str(tmp_path))
    return built


@posix_only
def test_nothing_unread_means_nothing_is_launched(fleet):
    result = fleet.sweep()
    assert result["quiet"] is True and result["rows"] == []
    assert fleet.launches() == []


@posix_only
def test_a_session_with_unread_mail_is_woken_and_reads_it(fleet):
    fleet.send("pilot/front-door", "pilot/orchestrator", "hello")
    result = fleet.sweep()
    assert result["quiet"] is True
    assert [(row["endpoint"], row["state"]) for row in result["rows"]] == [("pilot/orchestrator", "read")]
    assert result["rows"][0]["read"] == ["hello"]
    launched = fleet.launches()
    assert [row["endpoint"] for row in launched] == ["pilot/orchestrator"]
    assert "UNTRUSTED-BODY" not in json.dumps(launched), "message text must never reach the command line or prompt"
    assert "mailbox_inbox" in launched[0]["stdin"]


@posix_only
def test_a_sweep_wake_in_background_mode_reports_the_idle_session_it_stopped(fleet):
    stub, state = fleet.tmp / "claude_stub.py", fleet.tmp / "background-state"
    stub.write_text(STUB, encoding="utf-8")
    state.mkdir()
    session, endpoint = fleet.orchestrator["session"], "pilot/orchestrator"
    holder = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"], start_new_session=True)
    (state / "old00000.row").write_text(json.dumps({
        "id": "old00000", "sessionId": session, "status": "idle", "state": "blocked", "kind": "background",
        "name": endpoint + "-g1", "pid": holder.pid}))
    path = Path(fleet.orchestrator["wake_profile"])
    profile = json.loads(path.read_text())
    profile.update(mode="background", prompt_via="argv", control=[sys.executable, str(stub), str(state), "control"],
                   argv=[sys.executable, str(stub), str(state), "reader", str(HELPER), str(fleet.root), endpoint,
                         "claude-code", session, str(fleet.base / "delivery"), str(fleet.tmp / "stub-record.json"),
                         "--bg", "--name", endpoint + "-g1", "--resume", session, "--"])
    path.write_text(json.dumps(profile))
    fleet.send("pilot/front-door", endpoint, "hello")
    try:
        row = fleet.sweep()["rows"][0]
    finally:
        holder.kill()
        holder.wait(timeout=5)
        for planted in state.glob("*.row"):
            pid = json.loads(planted.read_text())["pid"]
            if pid > 0:
                try:
                    os.killpg(pid, 9)
                except (ProcessLookupError, PermissionError):
                    pass
    assert row["state"] == "read" and row["read"] == ["hello"], row
    # The stop of the earlier idle session and how this turn ended must reach ROOT through the sweep row.
    assert row["stopped_idle"] == "old00000", row
    assert row["background"]["ended"] == "idle" and row["background"]["stop_confirmed"] is True, row


@posix_only
def test_a_conversation_runs_over_rounds_without_anyone_starting_each_turn(fleet):
    fleet.plan({"pilot/orchestrator": {"send": [{"message_id": "reply", "to": "pilot/front-door", "type": "info", "body": "Done."}]}})
    fleet.send("pilot/front-door", "pilot/orchestrator", "question")
    result = fleet.sweep("--rounds", "3")
    assert result["quiet"] is True and result["rounds"] == 2
    assert [row["endpoint"] for row in result["rows"]] == ["pilot/orchestrator", "pilot/front-door"]
    assert [row["state"] for row in result["rows"]] == ["read", "read"]


@posix_only
def test_one_round_leaves_the_reply_unread_and_says_so(fleet):
    fleet.plan({"pilot/orchestrator": {"send": [{"message_id": "reply", "to": "pilot/front-door", "type": "info", "body": "Done."}]}})
    fleet.send("pilot/front-door", "pilot/orchestrator", "question")
    result = fleet.sweep(expect=3)
    assert result["quiet"] is False
    assert result["still_unread"] == [{"initiative": "pilot", "endpoint": "pilot/front-door", "unread_count": 1}]


@posix_only
def test_a_session_that_ignores_its_mail_is_not_retried_in_the_same_sweep(fleet):
    fleet.plan({"pilot/orchestrator": {"ignore": True}})
    fleet.send("pilot/front-door", "pilot/orchestrator", "hello")
    result = fleet.sweep("--rounds", "4", expect=3)
    assert [row["state"] for row in result["rows"]] == ["woken_unread"]
    assert len(fleet.launches()) == 1
    assert result["still_unread"][0]["endpoint"] == "pilot/orchestrator"


@posix_only
def test_a_new_message_gives_an_ignoring_session_another_wake_in_a_later_sweep(fleet):
    fleet.plan({"pilot/orchestrator": {"ignore": True}})
    fleet.send("pilot/front-door", "pilot/orchestrator", "hello")
    fleet.sweep(expect=3)
    fleet.sweep(expect=3)
    assert len(fleet.launches()) == 2


def claude_transcript(fleet, session, minutes):
    folder = fleet.claude_home / "projects" / "-pilot"
    folder.mkdir(parents=True, exist_ok=True)
    rows = [{"type": "user", "timestamp": "2026-11-02T00:00:00.000Z", "message": {"content": "work"}},
            {"type": "assistant", "timestamp": "2026-11-02T%02d:%02d:00.000Z" % (minutes // 60, minutes % 60), "message": {"content": []}}]
    (folder / (session + ".jsonl")).write_text("".join(json.dumps(row) + "\n" for row in rows))


def codex_transcript(fleet, session, minutes):
    folder = fleet.tmp / "codex-home" / "sessions" / "2026"
    folder.mkdir(parents=True, exist_ok=True)
    rows = [{"type": "event_msg", "timestamp": "2026-11-02T00:00:00.000Z", "payload": {"type": "task_started"}},
            {"type": "event_msg", "timestamp": "2026-11-02T%02d:%02d:00.000Z" % (minutes // 60, minutes % 60), "payload": {"type": "task_complete"}}]
    (folder / ("rollout-2026-" + session + ".jsonl")).write_text("".join(json.dumps(row) + "\n" for row in rows))


@posix_only
def test_a_session_over_60_active_minutes_is_not_woken_and_needs_rotation(fleet):
    session = fleet.orchestrator["session"]
    claude_transcript(fleet, session, 60)
    fleet.send("pilot/front-door", "pilot/orchestrator", "hello")
    result = fleet.sweep(expect=3)
    assert fleet.launches() == []
    assert result["rows"][0]["state"] == "rotate_needed"
    assert result["rows"][0]["active_seconds"] == 3600
    assert result["rotate_needed"] == [{"initiative": "pilot", "endpoint": "pilot/orchestrator", "session": session}]


@posix_only
def test_a_session_under_60_active_minutes_is_woken_with_a_warning(fleet):
    claude_transcript(fleet, fleet.orchestrator["session"], 50)
    fleet.send("pilot/front-door", "pilot/orchestrator", "hello")
    row = fleet.sweep()["rows"][0]
    assert row["state"] == "read" and row["meter_before"] == "rotate_soon" and row["active_seconds_before"] == 3000


@pytest.mark.parametrize("minutes, state", [(70, "ok"), (80, "rotate_soon"), (90, "rotate_now")])
def test_the_sweep_tells_root_its_own_time_against_90_minutes(fleet, minutes, state):
    fleet.add_role("pilot/root", "codex-cli", session="root-session")
    codex_transcript(fleet, "root-session", minutes)
    result = fleet.sweep()
    assert result["root_time"] == [{"session": "root-session", "host": "codex-cli", "state": state,
                                    "active_seconds": minutes * 60, "limit": 5400}]


def test_one_root_serving_two_initiatives_is_reported_once(fleet):
    fleet.add_role("pilot/root", "codex-cli", session="root-session")
    second_initiative(fleet)
    provision("add-role", fleet.request(base=str(fleet.tmp / "initiatives" / "second"), endpoint="second/root", host="codex-cli",
                                        session="root-session"))
    codex_transcript(fleet, "root-session", 10)
    assert [row["session"] for row in fleet.sweep()["root_time"]] == ["root-session"]


def test_a_native_thread_with_unread_mail_is_left_for_root_to_message(fleet):
    fleet.add_role("pilot/lane/review", "codex", session="native-review")
    invoke(fleet.root, "publish", {"message_id": "for-review", "from": "pilot/orchestrator", "to": "pilot/lane/review", "host": "claude-code",
                                   "session": fleet.orchestrator["session"], "binding_generation": 1, "type": "info", "body": "Look."})
    result = fleet.sweep(expect=3)
    assert result["rows"] == [{"initiative": "pilot", "endpoint": "pilot/lane/review", "state": "message_thread", "session": "native-review",
                               "unread_count": 1, "meter_before": "no_transcript", "active_seconds_before": None}]
    assert fleet.launches() == []


def test_a_native_thread_past_its_limit_needs_rotation_instead(fleet):
    fleet.add_role("pilot/lane/review", "codex", session="native-review")
    codex_transcript(fleet, "native-review", 60)
    invoke(fleet.root, "publish", {"message_id": "for-review", "from": "pilot/orchestrator", "to": "pilot/lane/review", "host": "claude-code",
                                   "session": fleet.orchestrator["session"], "binding_generation": 1, "type": "info", "body": "Look."})
    assert fleet.sweep(expect=3)["rows"][0]["state"] == "rotate_needed"


@posix_only
def test_a_cli_session_with_no_transcript_is_not_woken(fleet):
    """Its active time is unknown, so a wake could carry it past its limit."""
    session = fleet.orchestrator["session"]
    (fleet.claude_home / "projects" / "-pilot" / (session + ".jsonl")).unlink()
    fleet.send("pilot/front-door", "pilot/orchestrator", "hello")
    result = fleet.sweep(expect=3)
    assert result["rows"] == [{"initiative": "pilot", "endpoint": "pilot/orchestrator", "state": "time_unknown", "session": session,
                               "unread_count": 1}]
    assert fleet.launches() == []


@posix_only
def test_a_session_whose_active_time_cannot_be_measured_is_not_woken(fleet):
    session = str(uuid.uuid4())
    invoke(fleet.root, "bind", {"endpoint": "pilot/lane/review", "host": "other-host", "session": session,
                                "expected_generation": 0})
    profile = json.loads(Path(fleet.orchestrator["wake_profile"]).read_text())
    profile.update(endpoint="pilot/lane/review", host="other-host", session=session, argv=["claude", "--resume", session])
    (fleet.base / "profiles" / "pilot%2Flane%2Freview-g1.wake.json").write_text(json.dumps(profile))
    invoke(fleet.root, "publish", {"message_id": "for-review", "from": "pilot/orchestrator", "to": "pilot/lane/review",
                                   "host": "claude-code", "session": fleet.orchestrator["session"], "binding_generation": 1,
                                   "type": "info", "body": "Look."})
    result = fleet.sweep(expect=3)
    assert result["rows"][0]["state"] == "meter_error"
    assert fleet.launches() == []


@posix_only
def test_an_endpoint_with_no_profile_is_reported_not_skipped_silently(fleet):
    invoke(fleet.root, "bind", {"endpoint": "pilot/lane/review", "host": "claude-code", "session": str(uuid.uuid4()),
                                "expected_generation": 0})
    invoke(fleet.root, "publish", {"message_id": "for-review", "from": "pilot/orchestrator", "to": "pilot/lane/review",
                                   "host": "claude-code", "session": fleet.orchestrator["session"], "binding_generation": 1,
                                   "type": "info", "body": "Look."})
    result = fleet.sweep(expect=3)
    assert result["rows"] == [{"initiative": "pilot", "endpoint": "pilot/lane/review", "state": "no_profile", "unread_count": 1}]


@posix_only
def test_an_unbound_endpoint_with_no_session_cannot_receive_mail_and_is_not_an_error(fleet):
    assert fleet.sweep()["quiet"] is True


@posix_only
def test_root_is_never_woken_and_its_queue_is_reported(fleet):
    fleet.add_role("pilot/root", "codex-cli", session="root-session")
    brief = fleet.base / "packet.md"
    brief.write_bytes(b"Run it.\n")
    invoke(fleet.root, "publish", {"message_id": "job-1", "from": "pilot/orchestrator", "to": "pilot/root",
                                   "host": "claude-code", "session": fleet.orchestrator["session"], "binding_generation": 1,
                                   "type": "job_request", "body": "Run.",
                                   "brief": {"path": str(brief), "sha256": hashlib.sha256(b"Run it.\n").hexdigest()}})
    result = fleet.sweep()
    assert fleet.launches() == [] and result["rows"] == []
    assert result["root_queue"] == [{"initiative": "pilot", "endpoint": "pilot/root", "unread_count": 1, "open_jobs": 1}]
    assert result["quiet"] is True


def test_root_reading_its_mail_clears_unread_but_not_its_open_jobs(fleet):
    fleet.add_role("pilot/root", "codex-cli", session="root-session")
    brief = fleet.base / "packet.md"
    brief.write_bytes(b"Run it.\n")
    orchestrator = {"from": "pilot/orchestrator", "to": "pilot/root", "host": "claude-code",
                    "session": fleet.orchestrator["session"], "binding_generation": 1}
    invoke(fleet.root, "publish", {**orchestrator, "message_id": "note", "type": "info", "body": "Please add a lane."})
    invoke(fleet.root, "publish", {**orchestrator, "message_id": "job-1", "type": "job_request", "body": "Run.",
                                   "brief": {"path": str(brief), "sha256": hashlib.sha256(b"Run it.\n").hexdigest()}})
    entry = {"initiative": "pilot", "endpoint": "pilot/root"}
    assert fleet.sweep()["root_queue"] == [{**entry, "unread_count": 2, "open_jobs": 1}]
    delivery = str(fleet.base / "delivery")
    page = invoke(fleet.root, "inbox", endpoint="pilot/root", delivery_dir=delivery, mark_read=True, limit=1)
    assert [row["message"]["message_id"] for row in page["messages"]] == ["note"]
    assert fleet.sweep()["root_queue"] == [{**entry, "unread_count": 1, "open_jobs": 1}]
    invoke(fleet.root, "inbox", endpoint="pilot/root", delivery_dir=delivery, mark_read=True)
    assert fleet.sweep()["root_queue"] == [{**entry, "unread_count": 0, "open_jobs": 1}]


def test_only_root_marks_mail_read_through_the_cli(fleet):
    delivery = str(fleet.base / "delivery")
    fleet.send("pilot/front-door", "pilot/orchestrator", "hello")
    refused = invoke(fleet.root, "inbox", endpoint="pilot/orchestrator", delivery_dir=delivery, mark_read=True, ok=False)
    assert "only root reads through the CLI" in refused["error"]
    fleet.add_role("pilot/root", "codex-cli", session="root-session")
    refused = invoke(fleet.root, "inbox", endpoint="pilot/root", mark_read=True, ok=False)
    assert refused["error"] == "--mark-read needs --delivery-dir"
    assert fleet.sweep("--dry-run", expect=3)["still_unread"][0]["endpoint"] == "pilot/orchestrator"


@posix_only
def test_a_replacement_without_a_new_profile_is_reported(fleet):
    brief = fleet.base / "brief.md"
    brief.write_bytes(b"Handoff.\n")
    invoke(fleet.root, "bind", invoke(fleet.root, "draft-handoff", {
        "endpoint": "pilot/orchestrator", "host": "claude-code", "session": str(uuid.uuid4()), "outgoing_stopped": True,
        "briefs": [{"path": str(brief), "sha256": hashlib.sha256(b"Handoff.\n").hexdigest()}]}))
    fleet.send("pilot/front-door", "pilot/orchestrator", "hello")
    result = fleet.sweep(expect=3)
    assert result["rows"][0]["state"] == "no_profile"
    assert fleet.launches() == []


def second_initiative(fleet, identifier="second", priority=1, project="stormheir"):
    base = fleet.tmp / "initiatives" / identifier
    provision("init", fleet.request(store=str(fleet.workspace.store), base=str(base), source=str(fleet.source), lanes=LANES,
                                    initiative={**INITIATIVE, "id": identifier, "priority": priority, "project": project,
                                                "repository": project}))
    for role in ("front-door", "orchestrator"):
        made = provision("add-role", fleet.request(base=str(base), endpoint=identifier + "/" + role, host="claude-code",
                                                   cwd=str(fleet.tmp)))
        started(fleet, "claude-code", made["session"])
    return base / "mailbox"


@posix_only
def test_every_initiative_is_swept_in_the_owners_priority_order(fleet):
    other = second_initiative(fleet)
    fleet.send("pilot/front-door", "pilot/orchestrator", "for-pilot")
    fleet.send("second/front-door", "second/orchestrator", "for-second", root=other)
    result = fleet.sweep()
    assert [row["initiative"] for row in result["rows"]] == ["second", "pilot"]
    assert result["quiet"] is True


@posix_only
def test_one_initiative_can_be_selected_and_paused_ones_are_left_alone(fleet):
    other = second_initiative(fleet)
    fleet.send("pilot/front-door", "pilot/orchestrator", "for-pilot")
    fleet.send("second/front-door", "second/orchestrator", "for-second", root=other)
    result = fleet.sweep("--initiative", "second", expect=0)
    assert [row["initiative"] for row in result["rows"]] == ["second"]
    fleet.workspace.run("update", {"initiative": "pilot", "source": "owner", "state": "paused"})
    result = fleet.sweep()
    assert result["rows"] == []
    assert fleet.sweep("--initiative", "unknown", expect=2)["error"] == "initiative is not registered: unknown"


@posix_only
def test_a_broken_mailbox_is_reported_and_the_others_still_run(fleet):
    other = second_initiative(fleet)
    fleet.send("pilot/front-door", "pilot/orchestrator", "for-pilot")
    (other / "manifest.json").write_text("{broken")
    result = fleet.sweep(expect=3)
    states = {row["initiative"]: row["state"] for row in result["rows"]}
    assert states == {"second": "mailbox_error", "pilot": "read"}
    assert next(row for row in result["rows"] if row["initiative"] == "second")["error"]


@posix_only
def test_a_refused_wake_is_reported_with_its_reason(fleet):
    fleet.send("pilot/front-door", "pilot/orchestrator", "hello")
    (fleet.root / ".write.lock").write_text("fixture active writer")
    result = fleet.sweep(expect=3)
    assert result["rows"][0]["state"] == "refused" and "writer is busy" in result["rows"][0]["error"]
    assert fleet.launches() == []


@posix_only
def test_a_dry_run_launches_nothing(fleet):
    fleet.send("pilot/front-door", "pilot/orchestrator", "hello")
    result = fleet.sweep("--dry-run", expect=3)
    assert [row["state"] for row in result["rows"]] == ["would_wake"]
    assert fleet.launches() == []
    assert not (fleet.base / "delivery" / "wakes").exists()


def test_bad_round_counts_are_refused(fleet):
    assert fleet.sweep("--rounds", "0", expect=2)["error"] == "invalid rounds"
    assert fleet.sweep("--rounds", "1000", expect=2)["error"] == "invalid rounds"
