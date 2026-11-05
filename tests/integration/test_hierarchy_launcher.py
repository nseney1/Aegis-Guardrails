"""The launcher starts, resumes and stops Codex roles and records every outcome.

Codex is the fake on PATH: a start prints the events a real start begins with, and a resume runs the fake host,
which reads the mailbox through the real adapter. These tests show the tools work together, not that a real
Codex session behaves this way.
"""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import time
import uuid

import pytest

from tests.integration.test_hierarchy_mailbox import ROOT, invoke
from tests.integration.test_hierarchy_provision import Setup


pytestmark = pytest.mark.skipif(os.name == "nt", reason="the launcher supports POSIX process groups only")
LAUNCHER = ROOT / "tools" / "hierarchy_launcher.py"
FAKE_CODEX = Path(__file__).with_name("hierarchy_fake_codex.py")
REVIEW = "pilot/lane/review"
START_PROMPT = "The Aegis launcher started this session for pilot/lane/review. Reply READY and take no other action."
ROOT_SESSION = "01a19a8e-3073-7af2-b5c0-d0c41fe82ada"


class Launch(Setup):
    def __init__(self, tmp_path):
        super().__init__(tmp_path)
        self.bin = tmp_path / "fake-bin"
        self.bin.mkdir()
        codex = self.bin / "codex"
        codex.write_text('#!/bin/sh\nexec "%s" "%s" "$@"\n' % (sys.executable, FAKE_CODEX), encoding="utf-8")
        codex.chmod(codex.stat().st_mode | stat.S_IXUSR)
        self.codex_log = tmp_path / "fake-codex.log"
        self.host_log = tmp_path / "fake-host.log"
        self.plan = tmp_path / "fake-host-plan.json"
        self.plan.write_text("{}", encoding="utf-8")

    def env(self, **extra):
        return {**os.environ, "PATH": str(self.bin) + os.pathsep + os.environ["PATH"], "PYTHONDONTWRITEBYTECODE": "1",
                "CODEX_HOME": str(self.tmp / "codex-home"), "FAKE_CODEX_LOG": str(self.codex_log),
                "FAKE_HOST_LOG": str(self.host_log), "FAKE_HOST_PLAN": str(self.plan), **extra}

    def argv(self, *words):
        return [sys.executable, "-I", str(LAUNCHER), "--base", str(self.base), *words]

    def run(self, *words, expect=0, timeout=60, **extra):
        result = subprocess.run(self.argv(*words), capture_output=True, text=True, timeout=timeout, env=self.env(**extra))
        assert not result.stderr, result.stderr
        assert result.returncode == expect, result.stdout
        return json.loads(result.stdout)

    def start_request(self, **request):
        path = self.tmp / ("start-%s.json" % uuid.uuid4().hex)
        path.write_text(json.dumps({"endpoint": REVIEW, **request}), encoding="utf-8")
        return path

    def start(self, expect=0, mode="", thread=None, environment=None, **request):
        return self.run("start", "--request", str(self.start_request(**request)), expect=expect, FAKE_CODEX_MODE=mode,
                        FAKE_CODEX_THREAD=thread or "019a" + uuid.uuid4().hex[:28], **(environment or {}))

    def started(self, mode="", thread=None, environment=None, **request):
        """A start left running, for tests that act on the launcher while it waits."""
        env = self.env(FAKE_CODEX_MODE=mode, FAKE_CODEX_THREAD=thread or "019a" + uuid.uuid4().hex[:28], **(environment or {}))
        return subprocess.Popen(self.argv("start", "--request", str(self.start_request(**request))), stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, env=env)

    def records(self, endpoint=REVIEW):
        folder = self.base / "launches" / endpoint.replace("/", "%2F")
        return [json.loads(path.read_text()) for path in sorted(folder.glob("*.json"))] if folder.exists() else []

    def binding(self, endpoint=REVIEW):
        return invoke(self.root, "status")["bindings"].get(endpoint)

    def publish_to(self, endpoint, identifier):
        sender = self.add_role("pilot/orchestrator", cwd=str(self.tmp))
        return invoke(self.root, "publish", {"message_id": identifier, "from": "pilot/orchestrator", "to": endpoint,
                                             "host": sender["host"], "session": sender["session"],
                                             "binding_generation": sender["generation"], "type": "info", "body": "UNTRUSTED-BODY"})


@pytest.fixture
def launch(tmp_path):
    built = Launch(tmp_path)
    built.init()
    return built


def census(session):
    rows = subprocess.run(["ps", "-ax", "-ww", "-o", "pid=,stat=,args="], capture_output=True, text=True, timeout=10).stdout
    return [int(line.split()[0]) for line in rows.splitlines()
            if session in line.split()[2:] and not line.split()[1].startswith("Z")]


def alive(pid):
    shown = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True, timeout=10).stdout.strip()
    return bool(shown) and not shown.startswith("Z")


def wait_until(condition, seconds=5.0):
    deadline = time.monotonic() + seconds
    while not condition():
        assert time.monotonic() < deadline, "condition not met within %.1f s" % seconds
        time.sleep(0.05)


def test_start_runs_the_start_argv_once_binds_the_session_and_records_it(launch):
    thread = "019a6c3e-1111-7222-8333-444455556666"
    answer = launch.start(thread=thread, cwd=str(launch.source))
    assert answer["schema"] == "aegis.hierarchy-launch/v1" and answer["action"] == "start"
    assert answer["state"] == "bound" and answer["host"] == "codex-cli"
    assert answer["session"] == thread and answer["generation"] == 1
    assert answer["exit_code"] == 0 and answer["timed_out"] is False
    assert launch.binding()["session"] == thread and launch.binding()["host"] == "codex-cli"
    profile = json.loads(Path(answer["wake_profile"]).read_text())
    assert profile["session"] == thread and profile["argv"][-2:] == ["resume", thread]
    assert Path(answer["connection"]).is_file()
    started = [json.loads(line) for line in launch.codex_log.read_text().splitlines()]
    assert len(started) == 1 and started[0]["argv"][-1] == START_PROMPT and "resume" not in started[0]["argv"]
    assert started[0]["cwd"] == str(launch.source)
    assert '"thread.started"' in Path(answer["log"]["stdout"]).read_text()
    [record] = launch.records()
    assert record == {key: value for key, value in answer.items() if key != "log"}
    folder = launch.base / "launches" / "pilot%2Flane%2Freview"
    [path] = folder.glob("*.json")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600 and stat.S_IMODE(folder.stat().st_mode) == 0o700
    # No temporary record name and no start lock outlive the start.
    assert sorted(entry.name for entry in folder.iterdir()) == sorted([path.name, "logs"])
    assert stat.S_IMODE((launch.base / "launches").stat().st_mode) == 0o700


def test_a_bound_endpoint_is_refused_and_the_refusal_is_recorded(launch):
    launch.start()
    refused = launch.start(expect=2)
    assert refused["error"] == "endpoint is already bound; resume it or hand it off"
    assert refused["state"] == "refused" and refused["session"] is None
    assert [row["state"] for row in launch.records()] == ["bound", "refused"]
    assert len(launch.codex_log.read_text().splitlines()) == 1


@pytest.mark.parametrize("request_change,error", [
    ({"base": "/elsewhere"}, "unexpected fields: base"),
    ({"session": "chosen"}, "unexpected fields: session"),
    ({"start_timeout_seconds": 0}, "invalid start_timeout_seconds"),
    ({"start_timeout_seconds": 3601}, "invalid start_timeout_seconds"),
    ({"start_timeout_seconds": "5"}, "invalid start_timeout_seconds"),
])
def test_malformed_start_requests_are_refused_before_anything_runs(launch, request_change, error):
    refused = launch.start(expect=2, **request_change)
    assert refused["error"] == error and refused["state"] == "refused"
    assert [row["error"] for row in launch.records()] == [error]
    assert not launch.codex_log.exists() and launch.binding() is None


def test_an_unknown_endpoint_is_refused_without_a_record(launch):
    refused = launch.start(expect=2, endpoint="pilot/lane/absent")
    assert refused == {"error": "unknown endpoint: pilot/lane/absent"}
    assert not (launch.base / "launches").exists()


def test_a_start_without_a_thread_is_recorded_as_failed_to_start(launch):
    answer = launch.start(expect=3, mode="no-thread")
    assert answer["state"] == "failed_to_start" and answer["session"] is None
    assert answer["exit_code"] == 1 and answer["timed_out"] is False
    assert launch.binding() is None and [row["state"] for row in launch.records()] == ["failed_to_start"]


def test_a_hung_start_is_stopped_at_its_timeout_and_left_unbound(launch):
    thread = "hung-" + uuid.uuid4().hex
    began = time.monotonic()
    answer = launch.start(expect=3, mode="hang", thread=thread, start_timeout_seconds=1)
    assert time.monotonic() - began < 5
    assert answer["state"] == "start_incomplete" and answer["session"] == thread and answer["timed_out"] is True
    assert launch.binding() is None and census(thread) == []


def test_a_start_that_fails_after_its_thread_is_not_bound(launch):
    thread = "failed-" + uuid.uuid4().hex
    answer = launch.start(expect=3, mode="fail-after-thread", thread=thread)
    assert answer["state"] == "start_incomplete" and answer["session"] == thread
    assert answer["exit_code"] == 4 and answer["timed_out"] is False
    assert launch.binding() is None


@pytest.mark.parametrize("endpoint,change,error", [
    ("pilot/lane/f2", {"source_repo": "SOURCE"},
     "the implementer role has no source views: they are for roles that read source and write none"),
    (REVIEW, {"timeout_seconds": 0}, "invalid timeout_seconds"),
])
def test_a_refused_binding_is_recorded_with_the_session_that_started(launch, endpoint, change, error):
    change = {key: str(launch.source) if value == "SOURCE" else value for key, value in change.items()}
    thread = "unbound-" + uuid.uuid4().hex
    answer = launch.start(expect=3, thread=thread, endpoint=endpoint, **change)
    assert answer["state"] == "bind_refused" and answer["session"] == thread and answer["error"] == error
    assert launch.binding(endpoint) is None and launch.records(endpoint)[-1]["state"] == "bind_refused"


def test_the_record_limit_refuses_before_starting(launch):
    folder = launch.base / "launches" / "pilot%2Flane%2Freview"
    folder.mkdir(parents=True)
    for number in range(10000):
        (folder / ("%05d.json" % number)).write_text("{}")
    refused = launch.start(expect=2)
    assert refused == {"error": "launch record limit reached for pilot/lane/review"}
    assert len(list(folder.glob("*.json"))) == 10000 and not launch.codex_log.exists()


def test_resume_runs_the_wake_with_the_bound_profile_and_records_it(launch):
    started = launch.start()
    launch.publish_to(REVIEW, "for-review")
    answer = launch.run("resume", "--endpoint", REVIEW)
    assert answer["action"] == "resume" and answer["state"] == "resumed"
    assert answer["session"] == started["session"] and answer["generation"] == 1
    assert answer["wake"]["state"] == "read" and answer["wake"]["exit_code"] == 0
    assert answer["wake"]["wake_id"].startswith("wake-") and answer["wake"]["timed_out"] is False
    assert answer["wake_exit_code"] == 0
    hosted = [json.loads(line) for line in launch.host_log.read_text().splitlines()]
    assert [row["endpoint"] for row in hosted] == [REVIEW] and hosted[0]["argv"][-2] == started["session"]
    assert [row["state"] for row in launch.records()] == ["bound", "resumed"]


def test_resume_dry_run_launches_nothing(launch):
    launch.start()
    launch.publish_to(REVIEW, "for-review")
    answer = launch.run("resume", "--endpoint", REVIEW, "--dry-run")
    assert answer["state"] == "resumed" and answer["dry_run"] is True
    assert answer["wake"] == {"exit_code": None, "state": "dry_run", "timed_out": None, "wake_id": None}
    assert answer["wake_exit_code"] == 0
    assert not launch.host_log.exists()


def test_resume_refuses_an_unbound_endpoint_and_records_it(launch):
    refused = launch.run("resume", "--endpoint", REVIEW, expect=2)
    assert refused["error"] == "endpoint has no binding" and refused["host"] is None
    assert [row["state"] for row in launch.records()] == ["refused"]


def test_resume_refuses_a_native_thread(launch):
    launch.add_role(REVIEW, "codex", session="native-review")
    refused = launch.run("resume", "--endpoint", REVIEW, expect=2)
    assert refused["error"] == "a native thread is resumed by its own app, not the launcher"
    assert refused["host"] == "codex" and refused["session"] == "native-review"


def test_resume_refuses_without_the_bindings_wake_profile(launch):
    Path(launch.start()["wake_profile"]).unlink()
    refused = launch.run("resume", "--endpoint", REVIEW, expect=2)
    path = launch.base / "profiles" / "pilot%2Flane%2Freview-g1.wake.json"
    assert refused["error"] == "no wake profile for the current binding: " + str(path)


def test_resume_mirrors_a_wake_refusal(launch):
    launch.start()
    (launch.root / ".wake-pilot%2Flane%2Freview.lock").write_text("{}")
    launch.publish_to(REVIEW, "for-review")
    refused = launch.run("resume", "--endpoint", REVIEW, expect=2)
    assert refused["state"] == "refused" and "a wake is already in progress" in refused["error"]
    assert refused["wake_exit_code"] == 2 and refused["wake"]["state"] is None


def test_stop_ends_the_process_group_of_a_hung_session(launch):
    session = launch.start()["session"]
    hung = subprocess.Popen(["sh", "-c", 'sleep 30 & exec codex exec --json hold "$0"', session], env=launch.env(FAKE_CODEX_MODE="hang",
                            FAKE_CODEX_THREAD=session), stdout=subprocess.DEVNULL, start_new_session=True)
    try:
        wait_until(lambda: census(session) == [hung.pid])
        children = [int(pid) for pid in subprocess.run(["pgrep", "-g", str(hung.pid)], capture_output=True, text=True,
                                                       timeout=10).stdout.split() if int(pid) != hung.pid]
        answer = launch.run("stop", "--endpoint", REVIEW, "--grace-seconds", "2")
        assert answer["action"] == "stop" and answer["state"] == "stopped" and answer["pids"] == [hung.pid]
        assert answer["wake_marker_present"] is False
        assert hung.wait(timeout=5) < 0
        wait_until(lambda: not any(alive(pid) for pid in children))
        assert [row["state"] for row in launch.records()] == ["bound", "stopped"]
    finally:
        if hung.poll() is None:
            os.killpg(hung.pid, 9)
            hung.wait(timeout=5)


def test_stop_with_nothing_running_reports_not_running_and_keeps_the_wake_marker(launch):
    launch.start()
    marker = launch.root / ".wake-pilot%2Flane%2Freview.lock"
    marker.write_text("{}")
    answer = launch.run("stop", "--endpoint", REVIEW)
    assert answer["state"] == "not_running" and answer["wake_marker_present"] is True and marker.exists()


def test_stop_refuses_a_background_claude_session_and_bad_grace(launch):
    launch.add_role("pilot/orchestrator", cwd=str(launch.tmp), background=True)
    refused = launch.run("stop", "--endpoint", "pilot/orchestrator", expect=2)
    assert refused["error"] == "a background claude session stops through claude stop; use the wake tool's control"
    assert launch.run("stop", "--endpoint", REVIEW, "--grace-seconds", "61", expect=2)["error"] == "invalid grace_seconds"
    assert launch.run("stop", "--endpoint", REVIEW, expect=2)["error"] == "endpoint has no binding"


def test_status_reads_back_bindings_and_records(launch):
    session = launch.start()["session"]
    launch.start(expect=2)
    shown = launch.run("status", "--endpoint", REVIEW)
    assert shown["schema"] == "aegis.hierarchy-launch-status/v1"
    row = shown["endpoints"][REVIEW]
    assert row["binding"] == {"host": "codex-cli", "session": session, "generation": 1}
    assert row["records"] == 2 and row["last"]["state"] == "refused"
    assert list(launch.run("status")["endpoints"]) == [REVIEW]
    empty = launch.run("status", "--endpoint", "pilot/lane/f2")["endpoints"]["pilot/lane/f2"]
    assert empty == {"binding": None, "last": None, "records": 0}


def test_start_refuses_root_and_records_it(launch):
    refused = launch.start(expect=2, endpoint="pilot/root")
    assert refused["error"] == "ROOT is the owner's session; bind it with add-role" and refused["state"] == "refused"
    assert [row["state"] for row in launch.records("pilot/root")] == ["refused"]
    assert not launch.codex_log.exists() and launch.binding("pilot/root") is None


def test_a_held_start_lock_refuses_a_second_start_and_a_start_releases_its_lock(launch):
    lock = launch.base / "launches" / "pilot%2Flane%2Freview" / ".start.lock"
    lock.parent.mkdir(parents=True)
    lock.write_text('{"pid": 1}')
    refused = launch.start(expect=2)
    assert refused["error"] == "a start is already running for pilot/lane/review; inspect %s if none is" % lock
    assert refused["state"] == "refused" and refused["host"] == "codex-cli"
    assert lock.read_text() == '{"pid": 1}' and not launch.codex_log.exists()
    lock.unlink()
    assert launch.start()["state"] == "bound" and not lock.exists()
    assert [row["state"] for row in launch.records()] == ["refused", "bound"]


def test_a_start_that_cannot_spawn_is_recorded_as_failed_to_start(launch):
    (launch.bin / "codex").unlink()
    # Only git on PATH, so a real codex elsewhere on PATH is never reached.
    (launch.bin / "git").symlink_to(shutil.which("git"))
    answer = launch.start(expect=3, environment={"PATH": str(launch.bin)})
    assert answer["state"] == "failed_to_start" and answer["session"] is None
    assert answer["error"] == "[Errno 2] No such file or directory: 'codex'"
    assert answer["exit_code"] is None and answer["timed_out"] is False
    assert Path(answer["log"]["stderr"]).is_file()
    assert [row["state"] for row in launch.records()] == ["failed_to_start"] and launch.binding() is None


def test_a_descendant_that_leaves_the_group_cannot_hold_the_start(launch):
    child = launch.tmp / "escaped.pid"
    began = time.monotonic()
    try:
        answer = launch.start(mode="escape", environment={"FAKE_CODEX_CHILD": str(child)})
        assert time.monotonic() - began < 10
        assert answer["state"] == "bound" and alive(int(child.read_text()))
    finally:
        if child.exists():
            os.kill(int(child.read_text()), signal.SIGKILL)


def test_a_child_left_in_the_starts_group_is_stopped_after_a_clean_start(launch):
    child = launch.tmp / "left.pid"
    answer = launch.start(mode="leave-child", environment={"FAKE_CODEX_CHILD": str(child)})
    assert answer["state"] == "bound" and answer["exit_code"] == 0
    wait_until(lambda: not alive(int(child.read_text())))


@pytest.mark.parametrize("mode,timeout,timed_out", [("", 300, False), ("hang", 1, True)])
def test_an_invalid_reported_session_is_a_failed_start_without_a_session(launch, mode, timeout, timed_out):
    answer = launch.start(expect=3, mode=mode, thread="bad/../id", start_timeout_seconds=timeout)
    assert answer["state"] == "failed_to_start" and answer["error"] == "the start reported an invalid session"
    assert answer["session"] is None and answer["timed_out"] is timed_out
    assert launch.binding() is None


@pytest.mark.parametrize("mode,number,state", [("hang", signal.SIGTERM, "start_incomplete"),
                                               ("hang", signal.SIGHUP, "start_incomplete"),
                                               ("silent-hang", signal.SIGINT, "failed_to_start")])
def test_an_interrupted_launcher_stops_its_start_and_records_it(launch, mode, number, state):
    thread = "interrupted-" + uuid.uuid4().hex
    logs = launch.base / "launches" / "pilot%2Flane%2Freview" / "logs"
    running = launch.started(mode=mode, thread=thread)
    try:
        if mode == "hang":
            wait_until(lambda: any('"thread.started"' in path.read_text() for path in logs.glob("*.stdout")))
        else:
            wait_until(launch.codex_log.exists)
        [started] = [json.loads(line) for line in launch.codex_log.read_text().splitlines()]
        running.send_signal(number)
        out, err = running.communicate(timeout=20)
        assert running.returncode == 3 and err == "", out + err
        answer = json.loads(out)
        assert answer["state"] == state and answer["error"] == "the launcher was interrupted"
        assert answer["session"] == (thread if state == "start_incomplete" else None)
        assert not alive(started["pid"]) and launch.binding() is None
        assert [row["state"] for row in launch.records()] == [state]
        assert not (logs.parent / ".start.lock").exists()
    finally:
        if running.poll() is None:
            running.kill()
            running.wait(timeout=5)


def test_a_busy_mailbox_writer_is_waited_for_before_binding(launch):
    lock = launch.root / ".write.lock"
    running = launch.started(environment={"FAKE_CODEX_TOUCH": str(lock)})
    try:
        wait_until(lock.exists)
        time.sleep(1)
        lock.unlink()
        out, err = running.communicate(timeout=30)
        assert running.returncode == 0 and err == "", out + err
        assert json.loads(out)["state"] == "bound" and launch.binding() is not None
    finally:
        if running.poll() is None:
            running.kill()
            running.wait(timeout=5)


def test_a_writer_busy_past_the_wait_is_recorded_as_bind_busy_and_can_be_bound(launch):
    lock = launch.root / ".write.lock"
    thread = "019a6c3e-2222-7222-8333-444455556666"
    answer = launch.start(expect=3, thread=thread, environment={"FAKE_CODEX_TOUCH": str(lock)})
    assert answer["state"] == "bind_busy" and answer["session"] == thread
    assert answer["error"] == "mailbox writer is busy; inspect an abandoned lock before retrying"
    assert launch.binding() is None
    lock.unlink()
    launch.add_role(REVIEW, "codex-cli", session=thread)
    assert launch.binding()["session"] == thread


def test_status_reports_an_unreadable_newest_record_and_still_lists_every_endpoint(launch):
    launch.start()
    launch.run("stop", "--endpoint", "pilot/lane/f2", expect=2)
    torn = launch.base / "launches" / "pilot%2Flane%2Freview" / "99999999T000000000000Z-torn.json"
    torn.write_text("")
    row = launch.run("status", "--endpoint", REVIEW)["endpoints"][REVIEW]
    assert row["last"] is None and row["unreadable"] == str(torn) and row["records"] == 2
    listed = launch.run("status")["endpoints"]
    assert listed[REVIEW]["unreadable"] == str(torn) and listed["pilot/lane/f2"]["last"]["state"] == "refused"
    assert "unreadable" not in listed["pilot/lane/f2"]


def test_stop_refuses_root_and_a_native_thread_and_signals_nothing(launch):
    launch.add_role("pilot/root", "codex", session=ROOT_SESSION)
    launch.add_role(REVIEW, "codex", session="native-review")
    named = [subprocess.Popen(["sh", "-c", "sleep 30; :", session], start_new_session=True)
             for session in (ROOT_SESSION, "native-review")]
    try:
        wait_until(lambda: census(ROOT_SESSION) and census("native-review"))
        root = launch.run("stop", "--endpoint", "pilot/root", expect=2)
        assert root["error"] == "ROOT is the owner's session; the launcher does not stop it"
        assert root["state"] == "refused" and root["session"] == ROOT_SESSION
        native = launch.run("stop", "--endpoint", REVIEW, expect=2)
        assert native["error"] == "a native thread is stopped by its own app, not the launcher"
        assert native["state"] == "refused" and native["host"] == "codex"
        assert [row["state"] for row in launch.records("pilot/root") + launch.records()] == ["refused", "refused"]
        assert all(process.poll() is None for process in named)
    finally:
        for process in named:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)


def hold(launch, session, script, *words, **popen):
    """A process naming the session, kept running the way a hung codex turn is."""
    return subprocess.Popen(["sh", "-c", script, *words], env=launch.env(FAKE_CODEX_MODE="hang", FAKE_CODEX_THREAD=session,
                            HELD_SESSION=session), stdout=subprocess.DEVNULL, **popen)


def group(pid):
    return [int(member) for member in subprocess.run(["pgrep", "-g", str(pid)], capture_output=True, text=True,
                                                     timeout=10).stdout.split()]


def test_stop_spares_a_caller_that_names_the_session(launch):
    session = launch.start()["session"]
    hung = hold(launch, session, 'exec codex exec --json hold "$0"', session, start_new_session=True)
    caller = subprocess.Popen(["sh", "-c", '"$1" -I "$2" --base "$3" stop --endpoint "$4" --grace-seconds 2; echo "exit=$?"',
                               session, sys.executable, str(LAUNCHER), str(launch.base), REVIEW], stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True, env=launch.env(), start_new_session=True)
    try:
        wait_until(lambda: hung.pid in census(session))
        out, err = caller.communicate(timeout=30)
        assert caller.returncode == 0 and err == "", out + err
        answer, last = out.splitlines()
        assert last == "exit=0"
        answer = json.loads(answer)
        assert answer["state"] == "stopped" and answer["pids"] == [hung.pid] and caller.pid not in answer["pids"]
        assert hung.wait(timeout=5) < 0
    finally:
        for process in (hung, caller):
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)


def test_stop_spares_a_group_whose_leader_does_not_name_the_session(launch):
    session = launch.start()["session"]
    leader = hold(launch, session, 'sleep 30 & codex exec --json hold "$HELD_SESSION"; wait', start_new_session=True)
    try:
        wait_until(lambda: len(census(session)) == 1 and len(group(leader.pid)) == 3)
        [named] = census(session)
        others = [pid for pid in group(leader.pid) if pid not in (leader.pid, named)]
        answer = launch.run("stop", "--endpoint", REVIEW, "--grace-seconds", "2")
        assert answer["state"] == "stopped" and answer["pids"] == [named]
        assert leader.poll() is None and all(alive(pid) for pid in others)
    finally:
        os.killpg(leader.pid, signal.SIGKILL)
        leader.wait(timeout=5)


@pytest.mark.parametrize("grace", ["0", "1"])
def test_stop_kills_a_session_that_ignores_sigterm_after_the_grace(launch, grace):
    session = launch.start()["session"]
    stubborn = hold(launch, session, 'trap "" TERM; sleep 30; :', session, start_new_session=True)
    try:
        # The sleep starts after the trap is set, so a SIGTERM now is known to be ignored.
        wait_until(lambda: len(group(stubborn.pid)) == 2)
        answer = launch.run("stop", "--endpoint", REVIEW, "--grace-seconds", grace)
        assert answer["state"] == "stopped" and answer["pids"] == [stubborn.pid] and answer["grace_seconds"] == int(grace)
        assert stubborn.wait(timeout=5) == -signal.SIGKILL
    finally:
        if stubborn.poll() is None:
            os.killpg(stubborn.pid, signal.SIGKILL)
            stubborn.wait(timeout=5)


def test_stop_records_a_failed_process_census(launch):
    launch.start()
    refused = launch.run("stop", "--endpoint", REVIEW, expect=2, PATH=str(launch.bin))
    assert refused["error"] == "[Errno 2] No such file or directory: 'ps'" and refused["state"] == "refused"
    assert [row["state"] for row in launch.records()] == ["bound", "refused"]


def launcher_module():
    spec = importlib.util.spec_from_file_location("hierarchy_launcher_under_test", LAUNCHER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_resume_records_a_wake_tool_that_cannot_run(launch, monkeypatch, capsys):
    launch.start()
    module = launcher_module()

    def unrunnable(argv, **options):
        raise OSError(8, "Exec format error")
    monkeypatch.setattr(module.subprocess, "run", unrunnable)
    assert module.main(["--base", str(launch.base), "resume", "--endpoint", REVIEW]) == 2
    monkeypatch.undo()
    answer = json.loads(capsys.readouterr().out)
    assert answer["error"] == "[Errno 8] Exec format error" and answer["state"] == "refused"
    assert [row["state"] for row in launch.records()] == ["bound", "refused"]


def test_a_record_write_that_fails_part_way_leaves_no_torn_record(launch, monkeypatch, capsys):
    module = launcher_module()

    def failing(fd):
        raise OSError(28, "No space left on device")
    monkeypatch.setattr(module.os, "fsync", failing)
    assert module.main(["--base", str(launch.base), "stop", "--endpoint", REVIEW]) == 2
    monkeypatch.undo()
    assert json.loads(capsys.readouterr().out) == {"error": "[Errno 28] No space left on device"}
    folder = launch.base / "launches" / "pilot%2Flane%2Freview"
    assert list(folder.iterdir()) == []
    assert launch.run("status", "--endpoint", REVIEW)["endpoints"][REVIEW] == {"binding": None, "last": None, "records": 0}


def test_an_interrupt_during_the_bind_wait_is_recorded_and_releases_the_start_lock(launch):
    lock = launch.root / ".write.lock"
    thread = "019a6c3e-3333-7222-8333-444455556666"
    logs = launch.base / "launches" / "pilot%2Flane%2Freview" / "logs"
    running = launch.started(thread=thread, environment={"FAKE_CODEX_TOUCH": str(lock)})
    try:
        wait_until(lambda: lock.exists() and launch.codex_log.exists())
        [started] = [json.loads(line) for line in launch.codex_log.read_text().splitlines()]
        # The turn has ended and the launcher is waiting out the busy writer before it binds.
        wait_until(lambda: not alive(started["pid"]))
        time.sleep(0.5)
        running.send_signal(signal.SIGTERM)
        out, err = running.communicate(timeout=20)
        assert running.returncode == 3 and err == "", out + err
        answer = json.loads(out)
        assert answer["state"] == "start_incomplete" and answer["error"] == "the launcher was interrupted"
        assert answer["session"] == thread and answer["exit_code"] == 0
        assert [row["state"] for row in launch.records()] == ["start_incomplete"]
        assert not (logs.parent / ".start.lock").exists() and launch.binding() is None
    finally:
        if running.poll() is None:
            running.kill()
            running.wait(timeout=5)
    lock.unlink()
    launch.add_role(REVIEW, "codex-cli", session=thread)
    assert launch.binding()["session"] == thread


def test_a_census_that_fails_after_signals_were_sent_is_recorded_as_stop_failed(launch, monkeypatch, capsys):
    session = launch.start()["session"]
    hung = subprocess.Popen(["sh", "-c", 'exec codex exec --json hold "$0"', session], env=launch.env(FAKE_CODEX_MODE="hang",
                            FAKE_CODEX_THREAD=session), stdout=subprocess.DEVNULL, start_new_session=True)
    try:
        wait_until(lambda: census(session) == [hung.pid])
        module = launcher_module()
        real, calls = module.session_processes, []

        def failing_after_the_first(*args):
            calls.append(args)
            if len(calls) > 1:
                raise OSError(2, "No such file or directory: 'ps'")
            return real(*args)
        monkeypatch.setattr(module, "session_processes", failing_after_the_first)
        assert module.main(["--base", str(launch.base), "stop", "--endpoint", REVIEW, "--grace-seconds", "1"]) == 3
        monkeypatch.undo()
        answer = json.loads(capsys.readouterr().out)
        assert answer["state"] == "stop_failed" and answer["pids"] == [hung.pid]
        assert answer["error"] == "[Errno 2] No such file or directory: 'ps'"
        assert hung.wait(timeout=5) < 0
        assert [row["state"] for row in launch.records()] == ["bound", "stop_failed"]
    finally:
        if hung.poll() is None:
            os.killpg(hung.pid, 9)
            hung.wait(timeout=5)
