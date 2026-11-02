"""Published, woken and read stay separate states in the public CLI, adapter and wake tool.

Host processes here are stubs at the subprocess boundary. They show how the tools report
delivery, not that a real Claude or Codex session reads its mail.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

import pytest

from tests.integration.test_hierarchy_mailbox import HELPER, ROOT, invoke, mailbox_snapshot, message


WAKE = ROOT / "tools" / "hierarchy_wake.py"
BODY_SENTINEL = "UNTRUSTED-BODY-SENTINEL"
TARGET = "a/lane/review"
posix_only = pytest.mark.skipif(os.name == "nt", reason="wake tool process groups are POSIX only")

STUB = r'''
import json, os, subprocess, sys, time
mode, helper, root, endpoint, host, session, delivery, record = sys.argv[1:9]
with open(record, "w", encoding="utf-8") as stream:
    json.dump({"argv": sys.argv[1:], "stdin": sys.stdin.read()}, stream)
if mode == "reader":
    frames = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
              {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
               "params": {"name": "mailbox_inbox", "arguments": {}}}]
    subprocess.run([sys.executable, "-I", helper, "--root", root, "serve", "--endpoint", endpoint,
                    "--host", host, "--session", session, "--generation", "1", "--delivery-dir", delivery],
                   input="".join(json.dumps(f) + "\n" for f in frames), text=True, capture_output=True, check=True)
elif mode == "crash":
    sys.exit(7)
elif mode == "sleeper":
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    with open(record + ".child", "w", encoding="utf-8") as stream:
        stream.write(str(child.pid))
    time.sleep(60)
'''


class Pilot:
    def __init__(self, tmp_path, host="host-one", root=None, delivery=None):
        self.tmp = tmp_path
        self.root = root or tmp_path / "mailbox"
        self.delivery = delivery or tmp_path / "delivery"
        self.host = host
        self.session = "session-" + uuid.uuid4().hex
        self.record = tmp_path / "stub-record.json"
        self.stub = tmp_path / "host_stub.py"
        self.stub.write_text(STUB, encoding="utf-8")
        endpoints = {"a/front-door": {}, "a/orchestrator": {}, TARGET: {"kind": "reviewer"}}
        invoke(self.root, "init", {"schema": "aegis.hierarchy-pilot/v1", "endpoints": endpoints,
                                   "counterparts": [], "writer_limit": 3})
        for endpoint in endpoints:
            target = endpoint == TARGET
            invoke(self.root, "bind", {"endpoint": endpoint, "host": host if target else "host-one",
                                       "session": self.session if target else endpoint,
                                       "expected_generation": 0})

    def publish(self, identifier="note-1", body=BODY_SENTINEL):
        request = message(recipient=TARGET, identifier=identifier)
        request["body"] = body
        return invoke(self.root, "publish", request)

    def state(self, identifier="note-1"):
        return invoke(self.root, "delivery", delivery_dir=self.delivery, message_id=identifier)["message"]

    def summary(self):
        data = invoke(self.root, "delivery", delivery_dir=self.delivery, endpoint=TARGET)
        return data["endpoints"][TARGET]

    def adapter_argv(self, delivery=True):
        argv = [sys.executable, "-I", str(HELPER), "--root", str(self.root), "serve", "--endpoint", TARGET,
                "--host", self.host, "--session", self.session, "--generation", "1"]
        if delivery:
            argv += ["--delivery-dir", str(self.delivery if delivery is True else delivery)]
        return argv

    def adapter(self, calls, *, delivery=True):
        frames = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}]
        frames += [{"jsonrpc": "2.0", "id": index + 2, "method": "tools/call",
                    "params": {"name": name, "arguments": arguments}}
                   for index, (name, arguments) in enumerate(calls)]
        return subprocess.run(self.adapter_argv(delivery), input="".join(json.dumps(f) + "\n" for f in frames),
                              capture_output=True, text=True, timeout=15,
                              env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})

    def read_inbox(self, **arguments):
        result = self.adapter([("mailbox_inbox", arguments)])
        assert result.returncode == 0, result.stdout + result.stderr
        return json.loads(json.loads(result.stdout.splitlines()[-1])["result"]["content"][0]["text"])

    def profile(self, mode="reader", **changes):
        argv = [sys.executable, str(self.stub), mode, str(HELPER), str(self.root), TARGET, self.host,
                self.session, str(self.delivery), str(self.record)]
        document = {"schema": "aegis.hierarchy-wake-profile/v1", "endpoint": TARGET, "host": self.host,
                    "session": self.session, "generation": 1, "argv": argv, "cwd": str(self.tmp),
                    "timeout_seconds": 20, "prompt_via": "stdin"}
        document.update(changes)
        path = self.tmp / "wake-profile.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def wake(self, profile, *flags, home=None, timeout=30):
        env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
        if home is not None:
            env["HOME"] = str(home)
        result = subprocess.run([sys.executable, "-I", str(WAKE), "--root", str(self.root), "--delivery-dir",
                                 str(self.delivery), "--endpoint", TARGET, "--profile", str(profile), *flags],
                                capture_output=True, text=True, timeout=timeout, env=env)
        assert not result.stderr, result.stderr
        return result.returncode, json.loads(result.stdout)


@pytest.fixture
def pilot(tmp_path):
    return Pilot(tmp_path)


def test_published_message_is_not_read_until_the_adapter_returns_it(pilot):
    pilot.publish()
    state = pilot.state()
    assert state["state"] == "published"
    assert state["read_at"] is None and state["woken_at"] is None
    assert pilot.summary()["unread"] == ["note-1"]
    assert [row["message"]["message_id"] for row in pilot.read_inbox()["messages"]] == ["note-1"]
    state = pilot.state()
    assert state["state"] == "read"
    assert state["read_by"] == {"host": "host-one", "session": pilot.session, "generation": 1}
    summary = pilot.summary()
    assert summary["unread"] == [] and summary["unread_count"] == 0 and summary["read"] == 1


def test_cli_inbox_does_not_count_as_the_session_reading(pilot):
    pilot.publish()
    invoke(pilot.root, "inbox", endpoint=TARGET)
    assert pilot.state()["state"] == "published"


def test_only_messages_actually_returned_count_as_read(pilot):
    for index in range(3):
        pilot.publish("note-%d" % index)
    first = pilot.read_inbox(limit=1)
    assert [row["message"]["message_id"] for row in first["messages"]] == ["note-0"]
    summary = pilot.summary()
    assert summary["read"] == 1 and summary["unread"] == ["note-1", "note-2"]
    pilot.read_inbox(after_message_id=first["next_after"], limit=100)
    assert pilot.summary()["unread"] == []


def test_rereading_adds_no_receipts(pilot):
    pilot.publish()
    pilot.read_inbox()
    receipts = sorted((pilot.delivery / "reads").rglob("*.json"))
    assert len(receipts) == 1
    pilot.read_inbox()
    assert sorted((pilot.delivery / "reads").rglob("*.json")) == receipts


def test_adapter_without_delivery_dir_stays_read_only(pilot):
    pilot.publish()
    before = mailbox_snapshot(pilot.root)
    result = pilot.adapter([("mailbox_inbox", {})], delivery=False)
    assert result.returncode == 0 and not result.stderr
    assert mailbox_snapshot(pilot.root) == before


def test_delivery_dir_inside_the_mailbox_is_refused(pilot):
    inside = pilot.root / "receipts"
    result = pilot.adapter([], delivery=inside)
    assert result.returncode == 2
    assert json.loads(result.stdout)["error"] == "delivery directory must be outside the mailbox root"
    refused = invoke(pilot.root, "delivery", delivery_dir=inside, ok=False)
    assert refused["error"] == "delivery directory must be outside the mailbox root"
    assert not inside.exists()


def test_a_delivery_dir_above_the_mailbox_is_refused_by_every_tool(pilot):
    above = pilot.root.parent
    expected = "delivery directory must not contain the mailbox root"
    result = pilot.adapter([], delivery=above)
    assert result.returncode == 2 and json.loads(result.stdout)["error"] == expected
    assert invoke(pilot.root, "delivery", delivery_dir=above, ok=False)["error"] == expected


def test_the_mailbox_root_itself_is_not_a_delivery_dir(pilot):
    refused = invoke(pilot.root, "delivery", delivery_dir=pilot.root, ok=False)
    assert refused["error"] == "delivery directory must be outside the mailbox root"


def test_a_sibling_delivery_dir_is_accepted(pilot):
    pilot.publish()
    assert invoke(pilot.root, "delivery", delivery_dir=pilot.root.parent / "sibling")["endpoints"][TARGET]["published"] == 1


@posix_only
def test_wake_logs_cannot_land_inside_mailbox_history(tmp_path):
    parent = tmp_path / "pilot"
    parent.mkdir()
    pilot = Pilot(tmp_path, root=parent / "wake-logs", delivery=parent)
    pilot.publish()
    code, result = pilot.wake(pilot.profile(mode="ignore"))
    assert [row["message"]["message_id"] for row in invoke(pilot.root, "inbox", endpoint=TARGET)["messages"]] == ["note-1"]
    assert code == 2 and result["error"] == "delivery directory must not contain the mailbox root"
    assert not pilot.record.exists()


def test_unwritable_receipt_keeps_the_read_and_leaves_the_message_unread(pilot, tmp_path):
    pilot.publish()
    blocked = tmp_path / "blocked"
    blocked.write_text("a file where the delivery directory belongs")
    result = pilot.adapter([("mailbox_inbox", {})], delivery=blocked)
    assert result.returncode == 0
    response = json.loads(result.stdout.splitlines()[-1])["result"]
    assert "isError" not in response
    assert [r["message"]["message_id"] for r in json.loads(response["content"][0]["text"])["messages"]] == ["note-1"]
    assert "read receipt not recorded" in result.stderr
    assert pilot.state()["state"] == "published"


def read_with_a_connection_that_closes_first(pilot):
    process = subprocess.Popen(pilot.adapter_argv(), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}) + "\n")
    process.stdin.flush()
    assert json.loads(process.stdout.readline())["id"] == 1
    process.stdout.close()
    process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                    "params": {"name": "mailbox_inbox", "arguments": {}}}) + "\n")
    process.stdin.close()
    process.wait(timeout=15)
    stderr = process.stderr.read()
    process.stderr.close()
    return process.returncode, stderr


def test_a_response_that_never_reaches_the_connection_leaves_the_message_unread(pilot):
    pilot.publish()
    code, stderr = read_with_a_connection_that_closes_first(pilot)
    assert code == 0
    assert "Traceback" not in stderr and "Exception ignored" not in stderr
    assert pilot.state()["state"] == "published"
    assert pilot.summary()["unread"] == ["note-1"]
    assert not (pilot.delivery / "reads").exists()


@posix_only
def test_a_message_whose_response_failed_can_still_be_delivered_by_a_wake(pilot):
    pilot.publish()
    read_with_a_connection_that_closes_first(pilot)
    code, result = pilot.wake(pilot.profile())
    assert code == 0 and result["state"] == "read" and result["read"] == ["note-1"]


def fill_receipts(pilot, kind, count, **extra):
    folder = pilot.delivery / kind / TARGET
    folder.mkdir(parents=True)
    receipt = {"schema": "aegis.hierarchy-delivery-receipt/v1", "endpoint": TARGET, "host": pilot.host,
               "session": pilot.session, "generation": 1, "at": "2026-11-02T00:00:00.000000Z",
               "message_ids": ["seed-note"], **extra}
    raw = json.dumps(receipt)
    for number in range(count):
        (folder / ("20261102T000000000000Z-%05d.json" % number)).write_text(raw)
    return folder


def test_a_full_read_ledger_refuses_more_receipts_and_stays_readable(pilot):
    pilot.publish("seed-note")
    pilot.publish()
    folder = fill_receipts(pilot, "reads", 10000)
    result = pilot.adapter([("mailbox_inbox", {})])
    assert result.returncode == 0
    delivered = json.loads(json.loads(result.stdout.splitlines()[-1])["result"]["content"][0]["text"])["messages"]
    assert [row["message"]["message_id"] for row in delivered] == ["seed-note", "note-1"]
    assert "read receipt not recorded: delivery receipt history limit reached" in result.stderr
    assert len(list(folder.glob("*.json"))) == 10000
    summary = pilot.summary()
    assert summary["read"] == 1 and summary["unread"] == ["note-1"]
    assert not (folder / ".write.lock").exists()


def test_a_busy_receipt_folder_leaves_the_message_unread(pilot):
    pilot.publish()
    folder = pilot.delivery / "reads" / TARGET
    folder.mkdir(parents=True)
    lock = folder / ".write.lock"
    lock.write_text("fixture active writer")
    result = pilot.adapter([("mailbox_inbox", {})])
    assert result.returncode == 0 and "read receipt not recorded" in result.stderr
    assert pilot.state()["state"] == "published"
    assert lock.read_text() == "fixture active writer"


WAKE_RECEIPT = {"wake_id": "wake-old", "state": "exited", "exit_code": 0, "timed_out": False}


@posix_only
def test_a_wake_needs_room_for_both_receipts_before_it_launches(pilot):
    pilot.publish("seed-note")
    pilot.publish()
    folder = fill_receipts(pilot, "wakes", 9999, **WAKE_RECEIPT)
    code, result = pilot.wake(pilot.profile())
    assert code == 2 and result["error"] == "delivery receipt history limit reached"
    assert not pilot.record.exists()
    assert len(list(folder.glob("*.json"))) == 9999
    assert pilot.summary()["unread"] == ["seed-note", "note-1"]


@posix_only
def test_a_wake_can_use_the_last_two_receipts(pilot):
    pilot.publish("seed-note")
    folder = fill_receipts(pilot, "wakes", 9998, **WAKE_RECEIPT)
    code, result = pilot.wake(pilot.profile(mode="ignore"), timeout=60)
    assert code == 3 and result["state"] == "woken_unread"
    assert len(list(folder.glob("*.json"))) == 10000
    assert pilot.summary()["last_wake"]["state"] == "exited"


@pytest.mark.parametrize("change,error", [
    ({"session": "someone-else"}, "receipt does not match binding history"),
    ({"generation": 9}, "receipt does not match binding history"),
    ({"message_ids": ["unknown-message"]}, "receipt names a message not addressed to this endpoint"),
    ({"endpoint": "a/front-door"}, "wrong receipt schema or endpoint"),
    ({"extra": True}, "unexpected fields"),
])
def test_forged_or_mismatched_receipts_fail_loudly(pilot, change, error):
    pilot.publish()
    pilot.read_inbox()
    path = next((pilot.delivery / "reads").rglob("*.json"))
    path.write_text(json.dumps({**json.loads(path.read_text()), **change}))
    refused = invoke(pilot.root, "delivery", delivery_dir=pilot.delivery, endpoint=TARGET, ok=False)
    assert "malformed delivery receipt" in refused["error"] and error in refused["error"]


def test_truncated_receipt_fails_loudly(pilot):
    pilot.publish()
    pilot.read_inbox()
    next((pilot.delivery / "reads").rglob("*.json")).write_text("{truncated")
    refused = invoke(pilot.root, "delivery", delivery_dir=pilot.delivery, ok=False)
    assert "malformed delivery receipt" in refused["error"]


def test_unknown_message_and_endpoint_are_refused(pilot):
    assert "unknown message" in invoke(pilot.root, "delivery", delivery_dir=pilot.delivery,
                                       message_id="missing", ok=False)["error"]
    assert "unknown endpoint" in invoke(pilot.root, "delivery", delivery_dir=pilot.delivery,
                                        endpoint="a/lane/none", ok=False)["error"]


def test_summary_covers_every_endpoint_and_the_current_binding(pilot):
    pilot.publish()
    data = invoke(pilot.root, "delivery", delivery_dir=pilot.delivery)
    assert set(data["endpoints"]) == {"a/front-door", "a/orchestrator", TARGET}
    binding = data["endpoints"][TARGET]["binding"]
    assert binding == {"host": "host-one", "session": pilot.session, "generation": 1, "ready": True}
    assert "does not prove" in data["meaning"]


@posix_only
def test_nothing_unread_means_nothing_is_launched(pilot):
    code, result = pilot.wake(pilot.profile())
    assert code == 0 and result["state"] == "nothing_unread"
    assert not pilot.record.exists()
    assert not (pilot.delivery / "wakes").exists()


@posix_only
@pytest.mark.parametrize("prompt_via", ["stdin", "argv"])
def test_a_session_that_reads_its_mail_is_reported_as_read(pilot, prompt_via):
    pilot.publish()
    code, result = pilot.wake(pilot.profile(prompt_via=prompt_via))
    assert code == 0, result
    assert result["state"] == "read" and result["exit_code"] == 0 and result["timed_out"] is False
    assert result["read"] == ["note-1"] and result["still_unread"] == []
    assert pilot.state()["state"] == "read"
    assert pilot.state()["woken_at"] is not None
    observed = json.loads(pilot.record.read_text())
    prompt = observed["stdin"] if prompt_via == "stdin" else observed["argv"][-1]
    assert "mailbox_inbox" in prompt
    assert BODY_SENTINEL not in json.dumps(observed)
    assert "note-1" not in json.dumps(observed)


@posix_only
def test_a_session_that_never_reads_is_not_reported_as_delivered(pilot):
    pilot.publish()
    code, result = pilot.wake(pilot.profile(mode="ignore"))
    assert code == 3
    assert result["state"] == "woken_unread"
    assert result["exit_code"] == 0
    assert result["read"] == [] and result["still_unread"] == ["note-1"]
    state = pilot.state()
    assert state["state"] == "woken" and state["read_at"] is None
    summary = pilot.summary()
    assert summary["woken_unread"] == ["note-1"] and summary["last_wake"]["state"] == "exited"


@posix_only
def test_a_failed_turn_is_explicit(pilot):
    pilot.publish()
    code, result = pilot.wake(pilot.profile(mode="crash"))
    assert code == 3 and result["exit_code"] == 7 and result["state"] == "woken_unread"
    assert Path(result["log"]["stderr"]).is_file()


@posix_only
def test_a_missing_host_binary_never_counts_as_woken(pilot):
    pilot.publish()
    argv = [str(pilot.tmp / "no-such-host"), pilot.session]
    code, result = pilot.wake(pilot.profile(argv=argv))
    assert code == 3 and result["state"] == "failed_to_start" and result["exit_code"] is None
    assert "error" in result
    assert pilot.state()["state"] == "published"
    assert pilot.summary()["last_wake"]["state"] == "failed_to_start"


@posix_only
def test_an_unusable_log_location_never_counts_as_woken(pilot):
    pilot.publish()
    pilot.delivery.mkdir()
    (pilot.delivery / "wake-logs").write_text("a file where the log directory belongs")
    code, result = pilot.wake(pilot.profile())
    assert not pilot.record.exists()
    state = pilot.state()
    assert state["state"] == "published" and state["woken_at"] is None
    assert pilot.summary()["woken_unread"] == []
    assert code == 3 and result["state"] == "failed_to_start" and result["exit_code"] is None
    assert result["error"]
    assert pilot.summary()["last_wake"]["state"] == "failed_to_start"


def session_process_exists(session, deadline=2.0):
    stop = time.monotonic() + deadline
    while time.monotonic() < stop:
        listing = subprocess.run(["ps", "-ax", "-ww", "-o", "stat=,args="], capture_output=True, text=True).stdout
        if not any(session in line.split() and not line.lstrip().startswith("Z") for line in listing.splitlines()):
            return False
        time.sleep(0.05)
    return True


@posix_only
@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root ignores the directory permission")
def test_a_process_whose_start_cannot_be_recorded_is_stopped_and_not_counted(pilot):
    pilot.publish()
    folder = pilot.delivery / "wakes" / TARGET
    folder.mkdir(parents=True)
    folder.chmod(0o555)
    try:
        code, result = pilot.wake(pilot.profile(mode="sleeper"), timeout=20)
    finally:
        folder.chmod(0o755)
    assert code == 3 and result["state"] == "failed_to_start"
    assert "could not record the start" in result["error"]
    assert not session_process_exists(pilot.session)
    assert pilot.state()["state"] == "published"
    assert pilot.summary()["last_wake"] is None


def process_gone(pid, deadline=2.0):
    stop = time.monotonic() + deadline
    while time.monotonic() < stop:
        state = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True).stdout.strip()
        if not state or state.startswith("Z"):
            return True
        time.sleep(0.05)
    return False


@posix_only
def test_a_timeout_stops_the_whole_process_group_before_reporting(pilot):
    pilot.publish()
    code, result = pilot.wake(pilot.profile(mode="sleeper", timeout_seconds=1))
    assert code == 3 and result["state"] == "timed_out" and result["timed_out"] is True
    child = int(Path(str(pilot.record) + ".child").read_text())
    assert process_gone(child)
    assert pilot.state()["state"] == "woken"
    assert pilot.summary()["last_wake"]["timed_out"] is True


@posix_only
@pytest.mark.parametrize("change,error", [
    ({"session": "other-session"}, "profile does not match the current binding"),
    ({"host": "other-host"}, "profile does not match the current binding"),
    ({"generation": 2}, "profile does not match the current binding"),
    ({"endpoint": "a/orchestrator"}, "profile is for a different endpoint"),
    ({"argv": []}, "invalid argv"),
    ({"argv": [sys.executable, 5]}, "invalid argv"),
    ({"argv": [sys.executable, "--no-session-here"]}, "argv does not name the bound session"),
    ({"cwd": "relative/path"}, "path must be absolute"),
    ({"timeout_seconds": 0}, "invalid timeout_seconds"),
    ({"timeout_seconds": 86401}, "invalid timeout_seconds"),
    ({"prompt_via": "shell"}, "invalid prompt_via"),
    ({"schema": "other"}, "unsupported wake profile schema"),
    ({"run_this": "rm -rf /"}, "unexpected fields"),
])
def test_invalid_profiles_launch_nothing_and_record_nothing(pilot, change, error):
    pilot.publish()
    code, result = pilot.wake(pilot.profile(**change))
    assert code == 2 and error in result["error"]
    assert not pilot.record.exists()
    assert not (pilot.delivery / "wakes").exists()


@posix_only
def test_a_process_already_naming_the_session_blocks_the_wake(pilot):
    pilot.publish()
    busy = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)", pilot.session])
    try:
        code, result = pilot.wake(pilot.profile())
    finally:
        busy.kill()
        busy.wait(timeout=5)
    assert code == 2 and "session is already running" in result["error"]
    assert not pilot.record.exists()


@posix_only
@pytest.mark.parametrize("alive,expected", [(True, 2), (False, 0)])
def test_claude_session_table_blocks_only_a_live_session(tmp_path, alive, expected):
    pilot = Pilot(tmp_path, host="claude-code")
    pilot.publish()
    home = tmp_path / "home"
    (home / ".claude" / "sessions").mkdir(parents=True)
    if alive:
        pid = os.getpid()
    else:
        gone = subprocess.Popen([sys.executable, "-c", "pass"])
        gone.wait(timeout=5)
        pid = gone.pid
    (home / ".claude" / "sessions" / "1.json").write_text(json.dumps({"sessionId": pilot.session, "pid": pid}))
    code, result = pilot.wake(pilot.profile(), home=home)
    assert code == expected, result
    if alive:
        assert "session is already running" in result["error"]
    else:
        assert result["state"] == "read"


@posix_only
def test_a_wake_in_progress_is_not_doubled_and_its_lock_is_left_for_inspection(pilot):
    pilot.publish()
    folder = pilot.delivery / "wake-locks" / TARGET
    folder.mkdir(parents=True)
    lock = folder / ".wake.lock"
    lock.write_text("fixture active wake")
    code, result = pilot.wake(pilot.profile())
    assert code == 2 and "a wake is already in progress" in result["error"]
    assert not pilot.record.exists()
    assert lock.read_text() == "fixture active wake"


@posix_only
def test_dry_run_writes_nothing_and_launches_nothing(pilot):
    pilot.publish()
    code, result = pilot.wake(pilot.profile(), "--dry-run")
    assert code == 0 and result["state"] == "dry_run" and result["would_wake"] == ["note-1"]
    assert not pilot.record.exists()
    assert not pilot.delivery.exists()
