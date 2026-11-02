"""Claude roles can run as background sessions, so they show in the owner's session list.

The host is a stub at the subprocess boundary that follows the documented `claude --bg`,
`claude agents --json`, `claude stop` and `claude logs` behavior. It shows how the wake tool and
provisioning drive that interface, not that a real Claude host behaves this way.
"""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys

import pytest

from tests.integration.test_hierarchy_delivery import BODY_SENTINEL, HELPER, TARGET, Pilot, posix_only
from tests.integration.test_hierarchy_provision import setup  # noqa: F401  (fixture)

pytestmark = posix_only

STUB = r'''
import json, os, signal, subprocess, sys, time
state, words = sys.argv[1], sys.argv[2:]


def rows():
    found = []
    for name in sorted(os.listdir(state)):
        if name.endswith(".row"):
            with open(os.path.join(state, name), encoding="utf-8") as stream:
                found.append(json.load(stream))
    return found


def save(row):
    path = os.path.join(state, row["id"] + ".row")
    with open(path + ".tmp", "w", encoding="utf-8") as stream:
        json.dump(row, stream)
    os.replace(path + ".tmp", path)


def alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


if words[0] == "control":
    with open(os.path.join(state, "calls.log"), "a", encoding="utf-8") as log:
        log.write(json.dumps(words[1:]) + "\n")
    if words[1] == "agents":
        # A host list can briefly leave out a session that is still running; "hide-next" makes one look do that.
        hide = os.path.join(state, "hide-next")
        hidden = os.path.exists(hide)
        if hidden:
            os.remove(hide)
        print(json.dumps([{key: row[key] for key in ("id", "sessionId", "status", "state", "kind", "name", "pid",
                                                    "waitingFor") if key in row}
                          for row in rows() if row["status"] != "stopped" and alive(row["pid"]) and not hidden]))
    elif words[1] == "stop":
        for row in rows():
            if row["id"] == words[2] and not os.path.exists(os.path.join(state, "ignore-stop")):
                try:
                    os.killpg(row["pid"], signal.SIGTERM)
                except ProcessLookupError:
                    pass
                row["status"] = "stopped"
                save(row)
            if row["id"] == words[2] and os.path.exists(os.path.join(state, "hide-on-stop")):
                open(os.path.join(state, "hide-next"), "w").close()
    elif words[1] == "logs":
        print("terminal output of " + words[2])
        extra = os.path.join(state, "logs-extra")
        if os.path.exists(extra):
            with open(extra, encoding="utf-8") as stream:
                print(stream.read())
    sys.exit(0)

if words[0] == "turn":
    # Like a real background session, the turn's process does not carry its session ID in argv.
    identifier, mode, helper, root, endpoint, host, delivery = words[1:8]
    session = os.environ["STUB_SESSION"]
    if mode in ("reader", "flicker", "exits"):
        frames = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
                  {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "mailbox_inbox", "arguments": {}}}]
        subprocess.run([sys.executable, "-I", helper, "--root", root, "serve", "--endpoint", endpoint, "--host", host,
                        "--session", session, "--generation", "1", "--delivery-dir", delivery],
                       input="".join(json.dumps(f) + "\n" for f in frames), text=True, capture_output=True, check=True)
    if mode == "flicker":
        time.sleep(1.5)
        open(os.path.join(state, "hide-next"), "w").close()
    if mode == "exits":
        time.sleep(1.5)
        sys.exit(0)  # the session ends on its own; the host stops listing it
    if mode != "hang":
        time.sleep(2.5)  # visibly busy across more than one poll
        row = next(row for row in rows() if row["id"] == identifier)
        ends = os.path.join(state, "turn-ends.json")
        if os.path.exists(ends):  # the turn stops mid-way in the listed shape, e.g. at a dialog
            with open(ends, encoding="utf-8") as stream:
                row.update(json.load(stream))
        else:  # an idle session also shows state "blocked" on the real host
            row["status"], row["state"] = "idle", "blocked"
        save(row)
    while True:  # a background session stays alive after its turn until it is stopped
        time.sleep(1)

mode, helper, root, endpoint, host, session, delivery, record = words[:8]
with open(record, "w", encoding="utf-8") as stream:
    json.dump({"argv": words}, stream)
if mode == "launch-fails":
    sys.exit(7)
identifier = session[-8:]
if mode == "unlisted":  # the launcher reports success, but the host never lists the session
    print(identifier)
    sys.exit(0)
save({"id": identifier, "sessionId": session, "status": "busy", "state": "working", "kind": "background",
      "name": words[words.index("--name") + 1], "pid": -1})
child = subprocess.Popen([sys.executable, __file__, state, "turn", identifier, mode, helper, root, endpoint, host,
                          delivery], start_new_session=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, env={**os.environ, "STUB_SESSION": session})
row = next(row for row in rows() if row["id"] == identifier)
row["pid"] = child.pid
save(row)
if os.path.exists(os.path.join(state, "hide-after-launch")):
    open(os.path.join(state, "hide-next"), "w").close()  # the host's first look after the launch misses the session
print(identifier)
if mode == "orphan":
    sys.exit(7)  # the launcher fails after it has already started the session
'''


class Background:
    def __init__(self, tmp_path):
        self.pilot = Pilot(tmp_path, host="claude-code")
        self.state = tmp_path / "background-state"
        self.state.mkdir()
        self.stub = tmp_path / "claude_stub.py"
        self.stub.write_text(STUB, encoding="utf-8")
        self.home = tmp_path / "home"
        self.home.mkdir()

    def profile(self, stub_mode="reader", **changes):
        pilot = self.pilot
        argv = [sys.executable, str(self.stub), str(self.state), stub_mode, str(HELPER), str(pilot.root), TARGET,
                pilot.host, pilot.session, str(pilot.delivery), str(pilot.record), "--bg", "--name", TARGET + "-g1",
                "--resume", pilot.session, "--"]
        document = {"schema": "aegis.hierarchy-wake-profile/v1", "endpoint": TARGET, "host": pilot.host,
                    "session": pilot.session, "generation": 1, "argv": argv, "cwd": str(pilot.tmp), "timeout_seconds": 20,
                    "prompt_via": "argv", "mode": "background",
                    "control": [sys.executable, str(self.stub), str(self.state), "control"]}
        document.update(changes)
        path = pilot.tmp / "background-profile.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def wake(self, profile, timeout=60):
        return self.pilot.wake(profile, home=self.home, timeout=timeout)

    def calls(self):
        log = self.state / "calls.log"
        return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []

    def rows(self):
        return [json.loads(path.read_text()) for path in sorted(self.state.glob("*.row"))]

    def plant(self, status, **extra):
        """A background session for the same ID that is already alive, as the host would list it."""
        holder = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"], start_new_session=True)
        (self.state / "old00000.row").write_text(json.dumps({
            "id": "old00000", "sessionId": self.pilot.session, "status": status, "state": "blocked", "kind": "background",
            "name": TARGET + "-g1", "pid": holder.pid, **extra}))
        return holder

    def cleanup(self):
        for row in self.rows():
            if row["pid"] > 0:
                try:
                    os.killpg(row["pid"], signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass


@pytest.fixture
def background(tmp_path):
    built = Background(tmp_path)
    yield built
    built.cleanup()


def test_a_background_turn_is_waited_for_then_stopped_and_its_mail_reported_read(background):
    background.pilot.publish()
    code, result = background.wake(background.profile())
    assert code == 0, result
    assert result["state"] == "read" and result["read"] == ["note-1"] and result["timed_out"] is False
    identifier = background.pilot.session[-8:]
    assert result["background"] == {"id": identifier, "ended": "idle", "stop_confirmed": True,
                                    "exit_status": "unknown"}
    assert ["stop", identifier] in background.calls() and ["logs", identifier] in background.calls()
    assert all(row["status"] == "stopped" for row in background.rows())
    launched = json.loads(background.pilot.record.read_text())["argv"]
    assert launched[-2] == "--" and "mailbox_inbox" in launched[-1], "the prompt must follow the end of options"
    assert BODY_SENTINEL not in json.dumps(launched)
    assert "terminal output of " + identifier in Path(result["log"]["stdout"]).read_text()
    receipts = [json.loads(p.read_text()) for p in sorted((background.pilot.delivery / "wakes").rglob("*.json"))]
    assert [r["state"] for r in receipts] == ["started", "exited"]


def test_a_busy_background_session_is_not_woken_again(background):
    background.pilot.publish()
    holder = background.plant("busy")
    try:
        code, result = background.wake(background.profile())
    finally:
        holder.kill()
        holder.wait(timeout=5)
    assert code == 2 and "still working" in result["error"]
    assert not background.pilot.record.exists(), "nothing may launch while the session works"
    assert ["stop", "old00000"] not in background.calls()


def test_an_idle_background_session_is_stopped_before_its_next_turn(background):
    background.pilot.publish()
    holder = background.plant("idle")
    try:
        code, result = background.wake(background.profile())
    finally:
        holder.kill()
        holder.wait(timeout=5)
    assert code == 0 and result["state"] == "read", result
    assert result["stopped_idle"] == "old00000"
    calls = background.calls()
    assert calls.index(["stop", "old00000"]) < len(calls) - 1


def test_a_background_turn_that_outlives_its_timeout_is_stopped_and_reported(background):
    background.pilot.publish()
    code, result = background.wake(background.profile(stub_mode="hang", timeout_seconds=4))
    assert code == 3 and result["state"] == "timed_out" and result["timed_out"] is True
    assert result["background"]["ended"] == "timeout" and result["background"]["stop_confirmed"] is True
    assert ["stop", background.pilot.session[-8:]] in background.calls()


def test_a_failed_background_launch_is_recorded_as_failed_to_start(background):
    background.pilot.publish()
    code, result = background.wake(background.profile(stub_mode="launch-fails"))
    assert code == 3 and result["state"] == "failed_to_start" and "exit 7" in result["error"]
    assert not [call for call in background.calls() if call[0] == "stop"]
    receipts = [json.loads(p.read_text()) for p in sorted((background.pilot.delivery / "wakes").rglob("*.json"))]
    assert [r["state"] for r in receipts] == ["failed_to_start"]


def wake_lock(background):
    return background.pilot.root / (".wake-" + TARGET.replace("/", "%2F") + ".lock")


def test_a_failed_launch_that_left_a_session_stops_it_before_releasing_the_lock(background):
    background.pilot.publish()
    (background.state / "hide-after-launch").write_text("")
    code, result = background.wake(background.profile(stub_mode="orphan"))
    identifier = background.pilot.session[-8:]
    assert code == 3 and "exit 7" in result["error"], result
    # One missing look is not proof that the failed launcher left nothing running.
    assert ["stop", identifier] in background.calls(), result
    assert all(row["status"] == "stopped" for row in background.rows())
    assert result["state"] == "failed_to_start" and not wake_lock(background).exists()
    assert result["background"] == {"id": identifier, "ended": "launch_failed", "stop_confirmed": True,
                                    "exit_status": "unknown"}


def test_a_launch_whose_start_cannot_be_recorded_stops_the_session_it_started(background):
    background.pilot.publish()
    (background.state / "hide-after-launch").write_text("")
    # A folder where the wakes ledger takes its lock makes the "started" write fail after the launch.
    (background.pilot.delivery / "wakes" / TARGET / ".write.lock").mkdir(parents=True)
    code, result = background.wake(background.profile())
    identifier = background.pilot.session[-8:]
    assert code == 3 and "could not record the start" in result["error"], result
    assert ["stop", identifier] in background.calls(), result
    assert all(row["status"] == "stopped" for row in background.rows())
    assert result["state"] == "failed_to_start" and result["background"]["stop_confirmed"] is True


def test_a_failed_launch_whose_leftover_cannot_be_stopped_keeps_the_lock(background):
    background.pilot.publish()
    (background.state / "hide-after-launch").write_text("")
    (background.state / "ignore-stop").write_text("")
    code, result = background.wake(background.profile(stub_mode="orphan"))
    assert code == 3 and result["state"] == "stop_unconfirmed", result
    assert result["background"]["stop_confirmed"] is False and wake_lock(background).exists()


def test_a_busy_session_missing_from_one_look_is_still_not_woken_again(background):
    background.pilot.publish()
    holder = background.plant("busy")
    (background.state / "hide-next").write_text("")
    try:
        code, result = background.wake(background.profile())
    finally:
        holder.kill()
        holder.wait(timeout=5)
    assert code == 2 and "still working" in result["error"], result
    assert not background.pilot.record.exists(), "one missing look is not proof that nothing runs"


@pytest.mark.parametrize("ends", [
    {"status": "waiting", "state": "blocked"},  # seen live at a dialog (review r2 P2-2)
    {"status": "busy", "state": "blocked", "waitingFor": "permission prompt"},
    {"status": "idle", "state": "blocked", "waitingFor": "permission prompt"},
])
def test_a_turn_stopped_at_a_dialog_keeps_its_session_and_lock_and_asks_the_owner(background, ends):
    background.pilot.publish()
    (background.state / "turn-ends.json").write_text(json.dumps(ends))
    (background.state / "logs-extra").write_text("\x1b[1mDo you want to proceed?\x1b[0m\n")
    code, result = background.wake(background.profile())
    identifier = background.pilot.session[-8:]
    assert code == 3 and result["state"] == "needs_owner", result
    assert result["background"]["ended"] == "blocked" and result["background"]["dialog_prompt_seen"] is True
    assert ["stop", identifier] not in background.calls(), "a session waiting on a human is not stopped"
    assert ["logs", identifier] in background.calls() and wake_lock(background).exists()
    saved = Path(result["log"]["stdout"]).read_text()
    assert "Do you want to proceed?" in saved and "\x1b" not in saved


def test_an_unknown_host_status_is_never_taken_for_idle(background):
    background.pilot.publish()
    (background.state / "turn-ends.json").write_text(json.dumps({"status": "thinking", "state": "working"}))
    code, result = background.wake(background.profile(timeout_seconds=8))
    assert code == 3 and result["state"] == "needs_owner", result
    assert result["background"]["dialog_prompt_seen"] is False
    assert not [call for call in background.calls() if call[0] == "stop"], "no stop before the timeout"
    assert wake_lock(background).exists()


@pytest.mark.parametrize("status,extra", [
    ("waiting", {}), ("idle", {"waitingFor": "permission prompt"}), ("paused", {}),
])
def test_a_session_waiting_on_its_owner_is_neither_stopped_nor_woken_again(background, status, extra):
    background.pilot.publish()
    holder = background.plant(status, **extra)
    try:
        code, result = background.wake(background.profile())
    finally:
        holder.kill()
        holder.wait(timeout=5)
    assert code == 2 and "waiting on its owner" in result["error"], result
    assert not background.pilot.record.exists() and ["stop", "old00000"] not in background.calls()


def test_an_unconfirmed_stop_keeps_the_wake_lock(background):
    background.pilot.publish()
    (background.state / "ignore-stop").write_text("")
    code, result = background.wake(background.profile())
    assert code == 3 and result["state"] == "stop_unconfirmed", result
    assert result["background"]["stop_confirmed"] is False
    background.pilot.publish("note-2")
    again_code, again = background.wake(background.profile())
    assert again_code == 2 and "a wake is already in progress" in again["error"]


def wake_receipts(background):
    return [json.loads(p.read_text()) for p in sorted((background.pilot.delivery / "wakes").rglob("*.json"))]


def test_a_background_turn_reports_its_exit_status_as_unknown_not_success(background):
    background.pilot.publish()
    code, result = background.wake(background.profile())
    assert code == 0 and result["state"] == "read", result
    # The launcher returned and the session was stopped; nobody saw the session's own exit status.
    assert result["exit_code"] is None and result["background"]["exit_status"] == "unknown"
    finished = [r for r in wake_receipts(background) if r["state"] != "started"]
    assert len(finished) == 1 and finished[0]["exit_code"] is None, finished


def test_a_session_never_listed_before_a_short_timeout_is_reported_not_crashed(background):
    background.pilot.publish()
    code, result = background.wake(background.profile(stub_mode="unlisted", timeout_seconds=3))
    assert code == 3 and result["state"] == "timed_out" and result["timed_out"] is True, result
    assert result["background"]["id"] is None and result["background"]["ended"] == "timeout"
    assert result["background"]["stop_confirmed"] is True and result["exit_code"] is None
    assert not [call for call in background.calls() if call[0] in ("stop", "logs")], "there was no listed session to stop"
    assert [r["state"] for r in wake_receipts(background)] == ["started", "timed_out"]
    background.pilot.publish("note-2")
    again_code, again = background.wake(background.profile(stub_mode="unlisted", timeout_seconds=3))
    assert "a wake is already in progress" not in again.get("error", ""), "the lock must be released"


def test_a_null_timeout_is_refused_at_the_profile_boundary(background):
    background.pilot.publish()
    path = background.profile(timeout_seconds=None)
    code, result = background.wake(path)
    assert code == 2 and "invalid timeout_seconds" in result["error"], result
    assert not background.pilot.record.exists()


def test_a_session_briefly_missing_from_the_host_list_is_still_followed_and_stopped(background):
    background.pilot.publish()
    code, result = background.wake(background.profile(stub_mode="flicker"))
    assert code == 0 and result["state"] == "read", result
    identifier = background.pilot.session[-8:]
    assert result["background"]["ended"] == "idle" and result["background"]["stop_confirmed"] is True
    assert ["stop", identifier] in background.calls(), "a session that was only briefly unlisted must still be stopped"
    assert all(row["status"] == "stopped" for row in background.rows())


def test_a_session_that_really_ends_is_reported_exited_after_repeated_absence(background):
    background.pilot.publish()
    code, result = background.wake(background.profile(stub_mode="exits"))
    assert code == 0 and result["state"] == "read", result
    assert result["background"]["ended"] == "exited" and result["background"]["stop_confirmed"] is True, result
    assert result["exit_code"] is None and result["background"]["exit_status"] == "unknown"
    assert not [call for call in background.calls() if call[0] == "stop"]
    looks = [call for call in background.calls() if call[0] == "agents"]
    assert len(looks) >= 4, "one missing look is not an end"


def test_one_missing_look_after_stop_does_not_confirm_the_stop(background):
    background.pilot.publish()
    (background.state / "ignore-stop").write_text("")
    (background.state / "hide-on-stop").write_text("")
    code, result = background.wake(background.profile())
    assert code == 3 and result["state"] == "stop_unconfirmed", result
    background.pilot.publish("note-2")
    again_code, again = background.wake(background.profile())
    assert again_code == 2 and "a wake is already in progress" in again["error"], "the lock must stay"


@pytest.mark.parametrize("change,error", [
    ({"mode": "daemon"}, "invalid mode"),
    ({"mode": "background", "control": None}, "background mode needs its control command"),
    ({"mode": "background", "control": []}, "background mode needs its control command"),
    ({"mode": "background", "control": ["claude"], "prompt_via": "stdin"}, "background mode passes the prompt as an argument"),
    ({"mode": "background", "control": ["claude"], "host": "codex-cli"}, "profile does not match the current binding"),
    ({"control": ["claude"]}, "control is only for background mode"),
])
def test_invalid_background_profiles_launch_nothing(background, change, error):
    background.pilot.publish()
    document = json.loads(background.profile().read_text())
    document.update(change)
    document = {key: value for key, value in document.items() if value is not None}
    if change.get("mode") != "background" and "control" in change and "mode" not in change:
        document.pop("mode")
    path = background.pilot.tmp / "changed-profile.json"
    path.write_text(json.dumps(document))
    code, result = background.wake(path)
    assert code == 2 and error in result["error"], result
    assert not background.pilot.record.exists()


def test_background_mode_is_for_claude_only(tmp_path):
    built = Background(tmp_path)
    (tmp_path / "codex").mkdir()
    built.pilot = Pilot(tmp_path / "codex", host="codex-cli")
    built.pilot.publish()
    code, result = built.wake(built.profile())
    assert code == 2 and "background mode is for claude-code" in result["error"]
    assert not built.pilot.record.exists()


def test_a_background_claude_role_gets_a_named_background_start_and_wake(setup):  # noqa: F811
    role = setup.add_role("pilot/orchestrator", cwd=str(setup.tmp), background=True, model="claude-opus-5-5")
    profile = json.loads(Path(role["wake_profile"]).read_text())
    for argv, session_flag in ((profile["argv"], "--resume"), (role["start_argv"], "--session-id")):
        assert argv[0] == "claude" and argv[1] == "--bg"
        assert argv[argv.index("--name") + 1] == "pilot/orchestrator-g1"
        assert argv[argv.index(session_flag) + 1] == role["session"]
        assert argv[argv.index("--permission-mode") + 1] == "dontAsk", "print-only prompt flags do not apply here"
        assert argv[-1] == "--", "the prompt goes after the end of options, past the variadic --allowedTools"
        for print_only in ("--print", "--output-format", "--verbose", "--permission-prompts"):
            assert print_only not in argv
        assert "--restricted" in argv and "--strict-mcp-config" in argv and "--tools=Read,Glob,Grep" in argv
    assert profile["mode"] == "background" and profile["control"] == ["claude"] and profile["prompt_via"] == "argv"
    assert role["prompt_via"] == "argv" and role["start_prompt_via"] == "argv"
    assert "stays idle" in role["background"]


def test_print_mode_stays_the_default(setup):  # noqa: F811
    role = setup.add_role("pilot/orchestrator", cwd=str(setup.tmp))
    profile = json.loads(Path(role["wake_profile"]).read_text())
    assert "mode" not in profile and "--print" in profile["argv"] and "--bg" not in profile["argv"]
    assert "background" not in role


@pytest.mark.parametrize("endpoint,host,changes,error", [
    ("pilot/lane/f2", "codex-cli", {"session": "s-1", "cwd": None}, "background is only for claude-code roles"),
    ("pilot/root", "claude-code", {"session": "root-session"}, "background is only for claude-code roles"),
    ("pilot/orchestrator", "claude-code", {"background": "yes"}, "invalid background"),
])
def test_background_is_refused_where_it_cannot_apply(setup, endpoint, host, changes, error):  # noqa: F811
    changes = {"background": True, **changes}
    if changes.get("cwd", "") is None:
        changes["cwd"] = str(setup.source)
    result = setup.add_role(endpoint, host, expect=2, **changes)
    assert error in result["error"]


def test_switching_a_bound_claude_role_to_background_keeps_its_binding(setup):  # noqa: F811
    first = setup.add_role("pilot/orchestrator", cwd=str(setup.tmp))
    second = setup.add_role("pilot/orchestrator", cwd=str(setup.tmp), session=first["session"], background=True)
    assert second["generation"] == first["generation"] == 1 and second["session"] == first["session"]
    assert second["wake_profile"] == first["wake_profile"]
    assert json.loads(Path(second["wake_profile"]).read_text())["mode"] == "background"
