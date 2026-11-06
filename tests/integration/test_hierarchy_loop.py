"""The loop service runs the router, the durable sweep and run-open on a schedule, and reports what holds.

Every step is the real tool as a child process. The hosts are the fake host, and PATH is only the fake
binaries plus links to the tools the steps need, so no real model binary can start. These tests show the
tools work together on fixtures, not that real sessions behave this way.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time

import pytest

from tests.integration.test_hierarchy_jobs import Shop
from tests.integration.test_hierarchy_lifecycle import Ledger, request
from tests.integration.test_hierarchy_mailbox import ROOT, invoke
from tests.integration.test_hierarchy_provision import provision
from tests.integration.test_hierarchy_sweep import EVIDENCE, SealedFleet, ago, codex_transcript


LOOP = ROOT / "tools" / "hierarchy_loop.py"
pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"),
                                reason="run-open reads /proc and the wake supports POSIX process groups only")
# Loads the loop with one step's tool swapped for a script, which is how a test makes a step misbehave.
SWAPPED = """
import importlib.util, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location("hierarchy_loop", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.TOOLS[sys.argv[2]] = Path(sys.argv[3])
sys.exit(module.main(sys.argv[4:]))
"""
# Like SWAPPED, but this process holds a shared flock on a lock file, as a status probe does, for 0.3 s.
PROBED = """
import fcntl, importlib.util, os, sys, threading
from pathlib import Path
spec = importlib.util.spec_from_file_location("hierarchy_loop", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
descriptor = os.open(sys.argv[2], os.O_RDONLY)
fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
threading.Timer(0.3, os.close, [descriptor]).start()
sys.exit(module.main(sys.argv[3:]))
"""
EMPTY_SWEEP = {"rows": [], "still_unread": [], "root_queue": [], "root_time": []}
STAMP = r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z"
WAKE_ID = r"wake-[0-9a-f]{32}"


def router_policy(tmp_path):
    (tmp_path / "probe").mkdir()
    policy = Ledger(tmp_path / "probe", initialize=False).policy
    actors = {**policy["actors"], "router-2": {**policy["actors"]["router-1"], "generation": 2}}
    return {"actors": actors, "successors": {**policy["successors"], "router-1": "router-2"}}


class World(SealedFleet):
    """One team, `pilot`, with a router endpoint, a journal, a registered checkout and root's recipes."""

    make_checkout, head, publish, request_job = Shop.make_checkout, Shop.head, Shop.publish, Shop.request_job
    command = staticmethod(Shop.command)

    def __init__(self, tmp_path, policy_changes=None):
        super().__init__(tmp_path)
        found = shutil.which("git")
        assert found, "run-open inspects the checkout with git"
        (self.bin / "git").symlink_to(found)
        provision("init", self.init_request(roles=["router"]))
        self.front_door = self.add_role("pilot/front-door", cwd=str(tmp_path))
        self.orchestrator = self.add_role("pilot/orchestrator", cwd=str(tmp_path))
        self.add_role("pilot/router", cwd=str(tmp_path))
        self.add_role("pilot/root", "codex-cli", session="root-session")
        self.ledger = Ledger(tmp_path, policy_changes=policy_changes)
        self.checkout = self.make_checkout("checkout")
        self.workspace.run("update", {"initiative": "pilot", "source": "owner", "checkouts": [str(self.checkout)]})
        self.recipes_path = tmp_path / "recipes.json"
        self.recipes_path.write_text(json.dumps({
            "schema": "aegis.hierarchy-job-recipes/v1", "python": sys.executable, "path": ["/usr/bin", "/bin"],
            "identity": {"name": "Hierarchy Root", "email": "root@example.invalid"},
            "recipes": {"ok": self.command(["$python", "-c", "print('job output')"])}}), encoding="utf-8")
        self.state_dir = tmp_path / "loop-state"

    @property
    def status_path(self):
        return self.state_dir / "status.json"

    def lock_path(self, which):
        return Path(str(self.ledger.path if which == "lifecycle" else self.workspace.store) + ".loop.lock")

    def flags(self):
        return ["--lifecycle", str(self.ledger.path), "--store", str(self.workspace.store),
                "--recipes", str(self.recipes_path), "--state-dir", str(self.state_dir)]

    def loop(self, *args, expect=0, swap=None):
        if swap is None:
            argv = [sys.executable, "-I", "-B", str(LOOP)]
        else:
            step, script = swap
            argv = [sys.executable, "-I", "-B", "-c", SWAPPED, str(LOOP), step, str(script)]
        proc = subprocess.run(argv + self.flags() + list(args), capture_output=True, text=True, timeout=120,
                              env=self.env())
        assert not proc.stderr, proc.stderr
        assert proc.returncode == expect, proc.stdout
        return proc.stdout

    def once(self, expect=0, **options):
        return json.loads(self.loop("once", expect=expect, **options).splitlines()[-1])

    def status(self, *args, expect=0):
        out = self.loop("status", *args, expect=expect)
        return out if "--text" in args else json.loads(out)

    def approved(self, value):
        self.ledger.publish(value)
        self.ledger.approve(value)
        return value

    def inbox(self, endpoint):
        return invoke(self.root, "inbox", endpoint=endpoint)["messages"]

    def woken(self):
        return [row["endpoint"] for row in self.launches()]

    def script(self, name, text):
        path = self.tmp / name
        path.write_text(text, encoding="utf-8")
        return path


def holds(result, step=None):
    return {(row["step"], row["kind"], row.get("endpoint") or row.get("request_id") or row.get("job")): row
            for row in result["holds"] if step is None or row["step"] == step}


def step_states(result):
    return {row["step"]: row["state"] for row in result["steps"]}


@pytest.fixture
def world(tmp_path):
    return World(tmp_path)


def test_an_approved_request_is_routed_and_the_orchestrator_woken_in_the_same_pass(world):
    world.approved(request("feature-1", team="pilot"))

    result = world.once(expect=3)

    # The fake Orchestrator reads the route and answers nothing, which is the only hold.
    assert result["schema"] == "aegis.loop-status/v1"
    assert set(holds(result)) == {("sweep", "silent_role", "pilot/orchestrator")}
    assert step_states(result) == {"router_status": "ok", "route": "ok", "sweep": "hold", "run_open": "ok"}
    assert [row["step"] for row in result["steps"]] == ["router_status", "route", "sweep", "run_open"]
    route = next(row for row in result["steps"] if row["step"] == "route")
    assert (route["actor"], route["routed"]) == ("router-1", ["feature-1"])
    assert world.ledger.status()["requests"]["feature-1"]["routed"]["to"] == "pilot/orchestrator"
    assert world.woken() == ["pilot/orchestrator"]
    messages = world.inbox("pilot/orchestrator")
    assert [m["message"]["from"] for m in messages] == ["pilot/router"]
    assert json.loads(world.status_path.read_text()) == result


def test_a_second_pass_routes_nothing_wakes_nothing_and_writes_nothing(world):
    world.approved(request("feature-1", team="pilot"))
    first = world.once(expect=3)
    journal, launches = world.ledger.files(), world.launches()

    second = world.once(expect=3)

    assert step_states(second) == {"router_status": "ok", "route": "skipped", "sweep": "hold", "run_open": "ok"}
    assert set(holds(second)) == {("sweep", "silent_role", "pilot/orchestrator")}
    assert second["pass_id"] == first["pass_id"] + 1
    assert world.ledger.files() == journal
    assert world.launches() == launches
    assert len(world.inbox("pilot/orchestrator")) == 1


def test_mail_the_orchestrator_ignored_gets_no_second_turn_from_a_later_pass(world):
    world.plan({"pilot/orchestrator": {"ignore": True}})
    world.approved(request("feature-1", team="pilot"))
    first = world.once(expect=3)
    assert holds(first, "sweep")[("sweep", "woken_unread", "pilot/orchestrator")]["act"] == "root"

    second = world.once(expect=3)
    third = world.once(expect=3)

    assert set(holds(third)) == {("sweep", "ignored_mail", "pilot/orchestrator")}, "no second still_unread hold"
    held = holds(third, "sweep")[("sweep", "ignored_mail", "pilot/orchestrator")]
    assert (held["act"], held["initiative"], held["count"]) == ("root", "pilot", 2)
    assert held["first_seen"] == holds(second)[("sweep", "ignored_mail", "pilot/orchestrator")]["first_seen"]
    assert world.woken() == ["pilot/orchestrator"]
    assert len(world.inbox("pilot/orchestrator")) == 1


def test_a_second_instance_is_refused_while_the_first_holds_either_lock(world):
    for which, guarded in (("lifecycle", world.ledger.path), ("store", world.workspace.store)):
        path = world.lock_path(which)
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            refused = json.loads(world.loop("once", expect=2))
        finally:
            os.close(descriptor)
        assert refused == {"error": "loop already active for " + str(guarded)}
    assert not world.status_path.exists() and world.launches() == []
    assert not (world.ledger.path / ".loop.lock").exists() and not (world.workspace.store / ".loop.lock").exists()


def test_a_held_journal_lock_is_a_hold_and_after_three_passes_an_owner_hold_and_is_never_removed(world):
    # From ROOT, so reading it owes no answer and no silent_role hold outlives the lock.
    world.send("pilot/root", "pilot/orchestrator", "hello")
    lock = world.ledger.path / ".write.lock"
    lock.write_text("fixture writer")

    first = world.once(expect=3)

    assert step_states(first) == {"router_status": "hold", "route": "skipped", "sweep": "ok", "run_open": "ok"}
    held = holds(first)[("router_status", "journal_unavailable", None)]
    assert held["act"] == "root" and "busy" in held["detail"]
    assert world.woken() == ["pilot/orchestrator"], "the wake does not wait on the journal"
    assert first["consecutive_journal_unavailable"] == 1
    second = world.once(expect=3)
    assert ("router_status", "journal_lock", None) not in holds(second)

    third = world.once(expect=3)

    assert third["consecutive_journal_unavailable"] == 3
    owner = holds(third)[("router_status", "journal_lock", None)]
    assert owner["act"] == "owner" and str(world.ledger.path) in owner["detail"]
    assert lock.read_text() == "fixture writer"
    lock.unlink()
    recovered = world.once()
    assert recovered["consecutive_journal_unavailable"] == 0 and recovered["holds"] == []


def test_after_router_rotation_the_new_current_router_routes(tmp_path):
    world = World(tmp_path, router_policy(tmp_path))
    checkpoint = world.ledger.cli("checkpoint")["sha256"]
    world.ledger.event("succeed", actor="router-2", predecessor="router-1", checkpoint_sha256=checkpoint)
    world.approved(request("feature-1", team="pilot"))

    result = world.once()

    route = next(row for row in result["steps"] if row["step"] == "route")
    assert (route["actor"], route["routed"]) == ("router-2", ["feature-1"])
    assert world.ledger.status()["requests"]["feature-1"]["routed"]["actor"] == "router-2"


def test_root_is_never_woken_and_its_queue_is_reported_for_root(world):
    world.send("pilot/orchestrator", "pilot/root", "for-root")

    result = world.once(expect=3)

    queue = holds(result)[("sweep", "root_queue", "pilot/root")]
    assert (queue["act"], queue["initiative"]) == ("root", "pilot")
    assert world.launches() == []


def test_a_run_open_receipt_wakes_the_requester_on_the_next_pass(world):
    world.request_job("job-1", "ok")

    first = world.once(expect=3)

    jobs = next(row for row in first["steps"] if row["step"] == "run_open")
    assert (jobs["state"], jobs["rows"]) == ("ok", [{"job": "pilot/job-1", "state": "completed"}])
    assert world.launches() == [], "the receipt landed after this pass's wake"
    assert ("sweep", "root_queue", "pilot/root") in holds(first)

    second = world.once(expect=3)

    assert world.woken() == ["pilot/orchestrator"]
    woken = next(row for row in second["steps"] if row["step"] == "sweep")
    assert woken["woken"] == ["pilot/orchestrator"]
    assert [row["message"]["type"] for row in world.inbox("pilot/orchestrator")] == ["job_receipt", "job_receipt"]


def test_status_reads_not_running_stale_and_running(world):
    assert world.status(expect=3) == {"schema": "aegis.loop-status/v1", "state": "not_running", "last": None}
    world.once()
    assert world.status(expect=3)["state"] == "not_running"

    last = json.loads(world.status_path.read_text())
    last["finished_at"] = "2026-01-01T00:00:00.000000Z"
    last["interval"] = 30
    world.status_path.write_text(json.dumps(last))
    descriptor = os.open(world.lock_path("lifecycle"), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        stale = world.status(expect=3)
    finally:
        os.close(descriptor)
    assert (stale["state"], stale["last"]["pass_id"]) == ("stale", last["pass_id"])

    running = subprocess.Popen([sys.executable, "-I", "-B", str(LOOP), *world.flags(), "run", "--interval", "5",
                                "--passes", "3"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                               env=world.env())
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if json.loads(world.status_path.read_text())["pass_id"] > last["pass_id"]:
                break
            time.sleep(0.05)
        assert world.status()["state"] == "running"
    finally:
        running.send_signal(signal.SIGTERM)
        out, err = running.communicate(timeout=30)
    assert running.returncode == 0 and not err, out + err
    assert world.status(expect=3)["state"] == "not_running"


def test_status_text_groups_holds_by_who_must_act(world):
    world.send("pilot/orchestrator", "pilot/root", "for-root")
    (world.ledger.path / ".write.lock").write_text("fixture writer")
    world.once(expect=3)

    text = world.status("--text", expect=3)

    lines = text.splitlines()
    assert lines[0].startswith("loop: not_running")
    assert "root:" in lines and "owner:" not in lines
    root_block = lines[lines.index("root:") + 1:]
    assert any("sweep root_queue pilot/root" in line for line in root_block)
    assert any("router_status journal_unavailable" in line for line in root_block)


def test_sigterm_during_a_step_lets_it_finish_and_stops_before_the_next(world):
    world.approved(request("feature-1", team="pilot"))
    signalling = world.script("router-then-term.py", (
        "import os, signal, sys\n"
        "os.kill(os.getppid(), signal.SIGTERM)\n"
        "os.execv(sys.executable, [sys.executable, '-I', '-B', %r] + sys.argv[1:])\n") % str(
            ROOT / "tools" / "hierarchy_router.py"))

    result = json.loads(world.loop("run", "--interval", "5", "--passes", "3", swap=("router", signalling))
                        .splitlines()[-1])

    assert result["stopped"] is True
    assert [row["step"] for row in result["steps"]] == ["router_status"]
    assert result["steps"][0]["state"] == "ok"
    assert json.loads(world.status_path.read_text()) == result
    assert world.launches() == [] and world.inbox("pilot/orchestrator") == []
    assert world.ledger.status()["requests"]["feature-1"]["routed"] is None


def test_a_step_killed_mid_pass_is_a_hold_and_the_pass_continues(world):
    killed = world.script("killed.py", "import os, signal\nos.kill(os.getpid(), signal.SIGKILL)\n")

    result = world.once(expect=3, swap=("sweep", killed))

    held = holds(result)[("sweep", "child_failed", None)]
    assert (held["act"], held["detail"]) == ("owner", "killed by signal 9")
    assert step_states(result) == {"router_status": "ok", "route": "skipped", "sweep": "failed", "run_open": "ok"}
    assert json.loads(world.status_path.read_text()) == result


@pytest.mark.parametrize("args, error", [
    (["run", "--interval", "4"], "--interval must be between 5 and 600 seconds"),
    (["run", "--interval", "601"], "--interval must be between 5 and 600 seconds"),
    (["run", "--passes", "0"], "--passes must be a positive integer"),
    (["--max-jobs", "0", "once"], "--max-jobs must be a positive integer"),
])
def test_bad_arguments_are_refused(world, args, error):
    assert json.loads(world.loop(*args, expect=2)) == {"error": error}
    assert not world.status_path.exists()


def test_a_relative_path_is_refused(world):
    proc = subprocess.run([sys.executable, "-I", "-B", str(LOOP), "--lifecycle", "lifecycle", "--store",
                           str(world.workspace.store), "--recipes", str(world.recipes_path), "--state-dir",
                           str(world.state_dir), "once"], capture_output=True, text=True, timeout=30, env=world.env())
    assert proc.returncode == 2 and not proc.stderr
    assert json.loads(proc.stdout) == {"error": "--lifecycle must be absolute without traversal: got 'lifecycle'"}


def answering(world, name, outputs):
    """A step script that prints a fixed JSON for each subcommand (the last argument present wins) and exits."""
    return world.script(name, (
        "import json, sys\n"
        "outputs = %r\n"
        "for command, (code, value) in outputs.items():\n"
        "    if command in sys.argv[1:]:\n"
        "        print(json.dumps(value))\n"
        "        sys.exit(code)\n"
        "sys.exit(9)\n") % ({key: tuple(value) for key, value in outputs.items()},))


def test_a_broken_store_is_a_store_hold_for_root_and_never_counts_toward_the_journal_lock(world):
    (world.ledger.path / ".write.lock").write_text("fixture writer")
    assert world.once(expect=3)["consecutive_journal_unavailable"] == 1
    (world.ledger.path / ".write.lock").unlink()
    (Path(world.workspace.store) / "events" / "junk").write_text("x")

    passes = [world.once(expect=3) for _ in range(3)]

    for result in passes:
        held = holds(result, "router_status")
        assert set(held) == {("router_status", "store_unavailable", None)}
        assert held[("router_status", "store_unavailable", None)]["act"] == "root"
        assert held[("router_status", "store_unavailable", None)]["detail"] == "unexpected workspace store entry: junk"
        assert result["consecutive_journal_unavailable"] == 1, "a store failure neither counts nor clears"
        assert result["steps"][0] == {"step": "router_status", "state": "hold", "exit": 2, "source": "store"}
        assert step_states(result)["route"] == "skipped"


def test_a_store_failure_after_three_journal_failures_keeps_the_count_but_raises_no_journal_lock(world):
    lock = world.ledger.path / ".write.lock"
    lock.write_text("fixture writer")
    journal = [world.once(expect=3) for _ in range(3)]
    assert ("router_status", "journal_lock", None) in holds(journal[-1])
    lock.unlink()
    (Path(world.workspace.store) / "events" / "junk").write_text("x")

    result = world.once(expect=3)

    assert result["consecutive_journal_unavailable"] == 3
    assert set(holds(result, "router_status")) == {("router_status", "store_unavailable", None)}


def test_a_router_status_refusal_from_neither_journal_nor_store_is_a_router_status_error(world):
    refusing = answering(world, "refusing-router.py", {"status": (2, {"state": "hold", "error": "policy refused"})})

    passes = [world.once(expect=3, swap=("router", refusing)) for _ in range(3)]

    held = holds(passes[-1], "router_status")
    assert set(held) == {("router_status", "router_status_error", None)}
    assert (held[("router_status", "router_status_error", None)]["act"],
            held[("router_status", "router_status_error", None)]["detail"]) == ("root", "policy refused")
    assert [result["consecutive_journal_unavailable"] for result in passes] == [0, 0, 0]


def test_an_endpoint_failing_to_start_three_passes_running_is_skipped_until_the_owner_clears_status(world):
    log = world.tmp / "sweep-argv.log"
    failing = world.script("failing-sweep.py", (
        "import json, sys\n"
        "argv = sys.argv[1:]\n"
        "open(%r, 'a').write(json.dumps(argv) + '\\n')\n"
        "row = {'initiative': 'pilot', 'endpoint': 'pilot/orchestrator'}\n"
        "if '--skip' in argv and argv[argv.index('--skip') + 1] == 'pilot/orchestrator':\n"
        "    row['state'] = 'skipped'\n"
        "else:\n"
        "    row.update(state='failed_to_start', wake_exit=3,\n"
        "               error='could not record the start: [Errno 13] Permission denied')\n"
        "print(json.dumps({'rows': [row], 'root_queue': [], 'root_time': [],\n"
        "                  'still_unread': [{'initiative': 'pilot', 'endpoint': 'pilot/orchestrator', 'unread_count': 1}]}))\n"
        "sys.exit(3)\n") % str(log))
    skips = lambda: ["--skip" in json.loads(line) for line in log.read_text().splitlines()]  # noqa: E731

    passes = [world.once(expect=3, swap=("sweep", failing)) for _ in range(5)]

    assert skips() == [False, False, False, True, True]
    assert [holds(result)[("sweep", "failed_to_start", "pilot/orchestrator")]["count"] for result in passes[:3]] == [1, 2, 3]
    assert ("sweep", "start_failing", "pilot/orchestrator") not in holds(passes[1])
    owner = holds(passes[2])[("sweep", "start_failing", "pilot/orchestrator")]
    assert (owner["act"], owner["initiative"]) == ("owner", "pilot")
    assert owner["detail"] == ("pilot/orchestrator failed to start in 3 passes in a row; last error: could not record "
                               "the start: [Errno 13] Permission denied; the loop skips it until the owner deletes %s"
                               % world.status_path)
    for result in passes[3:]:
        assert set(holds(result, "sweep")) == {("sweep", "start_failing", "pilot/orchestrator")}
        assert holds(result)[("sweep", "start_failing", "pilot/orchestrator")]["detail"] == owner["detail"]
    assert holds(passes[4])[("sweep", "start_failing", "pilot/orchestrator")]["count"] == 3

    world.status_path.unlink()
    cleared = world.once(expect=3, swap=("sweep", failing))

    assert skips()[-1] is False
    assert ("sweep", "start_failing", "pilot/orchestrator") not in holds(cleared)


def test_a_start_failing_hold_survives_a_failed_sweep_step(world):
    log = world.tmp / "sweep-argv.log"
    status = {"schema": "aegis.loop-status/v1", "pass_id": 4, "consecutive_journal_unavailable": 0, "interval": None,
              "finished_at": "2026-11-05T00:00:00Z", "steps": [], "stopped": False, "holds": [
                  {"step": "sweep", "kind": "start_failing", "act": "owner", "detail": "why", "initiative": "pilot",
                   "endpoint": "pilot/orchestrator", "first_seen": "2026-11-05T00:00:00Z",
                   "last_seen": "2026-11-05T00:00:00Z", "count": 1}]}
    world.state_dir.mkdir()
    world.status_path.write_text(json.dumps(status))
    crashing = world.script("crashing-sweep.py", "import json, sys\nopen(%r, 'a').write(json.dumps(sys.argv[1:]))\n"
                                                 "sys.exit(1)\n" % str(log))

    result = world.once(expect=3, swap=("sweep", crashing))

    assert json.loads(log.read_text())[-2:] == ["--skip", "pilot/orchestrator"]
    kept = holds(result)[("sweep", "start_failing", "pilot/orchestrator")]
    assert (kept["detail"], kept["count"], kept["act"]) == ("why", 2, "owner")


def test_a_long_step_reads_as_running_with_its_name_not_stale(world):
    world.once()
    started, release = world.tmp / "sweep-started", world.tmp / "sweep-release"
    slow = world.script("slow-sweep.py", (
        "import json, os, sys, time\n"
        "open(%r, 'w').close()\n"
        "deadline = time.monotonic() + 5\n"
        "while not os.path.exists(%r) and time.monotonic() < deadline:\n"
        "    time.sleep(0.05)\n"
        "print(json.dumps(%r))\n") % (str(started), str(release), EMPTY_SWEEP))
    argv = [sys.executable, "-I", "-B", "-c", SWAPPED, str(LOOP), "sweep", str(slow), *world.flags(),
            "run", "--interval", "5", "--passes", "1"]
    running = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=world.env())
    try:
        deadline = time.monotonic() + 5
        while not started.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert started.exists()
        beat = json.loads(world.status_path.read_text())
        assert (beat["current_step"], beat["pass_id"], beat["interval"]) == ("sweep", 1, 5)
        # As if the last pass ended long ago and this step had run for two minutes: both are past 3 intervals.
        since = ago(120)
        world.status_path.write_text(json.dumps({**beat, "finished_at": "2026-01-01T00:00:00.000000Z",
                                                 "step_started_at": since}))

        shown = world.status()
        text = world.status("--text")
    finally:
        release.touch()
        out, err = running.communicate(timeout=30)
    assert (shown["state"], shown["last"]["current_step"]) == ("running", "sweep")
    assert 120 <= shown["step_age_seconds"] < 150
    head = re.fullmatch(r"loop: running \(pass 1, finished 2026-01-01T00:00:00.000000Z, interval 5 s\) "
                        r"step sweep running for (\d+)s since (.+)", text.splitlines()[0])
    assert head is not None, text
    assert 120 <= int(head.group(1)) < 150 and head.group(2) == since
    assert running.returncode == 0 and not err, out + err
    final = json.loads(world.status_path.read_text())
    assert (final["pass_id"], final["current_step"], final["step_started_at"]) == (2, None, None)


def test_a_status_file_that_cannot_be_written_is_reported_and_the_loop_goes_on(world):
    world.status_path.mkdir(parents=True)

    out = world.loop("run", "--interval", "5", "--passes", "2")

    first, second = [json.loads(line) for line in out.splitlines()]
    for result in (first, second):
        assert result["status_write_error"].startswith("[Errno 21] Is a directory")
    assert (first["pass_id"], second["pass_id"]) == (1, 2), "the counts carry on in memory"
    assert ("loop", "status_reset", None) in holds(first) and second["holds"] == []
    assert world.status_path.is_dir() and list(world.state_dir.iterdir()) == [world.status_path]


@pytest.mark.parametrize("change, error", [
    ({"holds": [{"step": "sweep"}]}, "status file has a bad hold"),
    ({"pass_id": "7"}, "status file has a bad pass_id"),
    ({"consecutive_journal_unavailable": None}, "status file has a bad consecutive_journal_unavailable"),
    ({"finished_at": "yesterday"}, "status file has a bad finished_at"),
])
def test_a_status_file_of_the_wrong_shape_restarts_the_counts_with_an_owner_hold(world, change, error):
    world.once()
    world.status_path.write_text(json.dumps({**json.loads(world.status_path.read_text()), **change}))
    message = "%s: %s" % (error, world.status_path)
    assert world.status(expect=2) == {"error": message}

    result = world.once(expect=3)

    assert result["pass_id"] == 1
    reset = holds(result)[("loop", "status_reset", None)]
    assert (reset["act"], reset["detail"]) == ("owner", "previous status.json was unusable, so the counts restarted: "
                                                        + message)
    assert world.once()["holds"] == []


def test_a_status_probes_shared_lock_does_not_refuse_a_starting_loop(world):
    world.lock_path("lifecycle").touch(mode=0o600)

    proc = subprocess.run([sys.executable, "-I", "-B", "-c", PROBED, str(LOOP), str(world.lock_path("lifecycle")),
                           *world.flags(), "once"], capture_output=True, text=True, timeout=60, env=world.env())

    assert proc.returncode == 0 and not proc.stderr, proc.stdout + proc.stderr
    assert json.loads(proc.stdout.splitlines()[-1])["pass_id"] == 1


@pytest.mark.parametrize("which", ["lifecycle", "store"])
def test_a_lock_path_that_is_a_symlink_is_refused_and_its_target_untouched(world, which):
    path, target = world.lock_path(which), world.tmp / "elsewhere.lock"
    path.symlink_to(target)
    message = {"error": "loop lock must not be a symlink: " + str(path)}

    assert json.loads(world.loop("once", expect=2)) == message
    assert not target.exists(), "a dangling link must not create its target"
    target.write_text("other journal's lock")
    assert json.loads(world.loop("once", expect=2)) == message
    if which == "lifecycle":
        assert world.status(expect=2) == message
    assert target.read_text() == "other journal's lock" and not world.status_path.exists()


def test_a_lock_path_that_is_not_a_regular_file_is_refused(world):
    os.mkfifo(world.lock_path("store"))

    assert json.loads(world.loop("once", expect=2)) == {
        "error": "loop lock is not a regular file: " + str(world.lock_path("store"))}
    assert not world.status_path.exists()


def test_router_request_rows_and_unresolved_escalations_become_holds(world):
    status = {"router": "router-1", "escalations": [
        {"request_id": "r-esc", "reason": "over budget", "team": "pilot", "root_decision": None},
        {"request_id": "r-decided", "reason": "over budget", "team": "pilot", "root_decision": {"decision": "deny"}}],
        "requests": [
            {"request_id": "r-held", "state": "held", "reason": "approval_expired", "detail": "expired at noon"},
            {"request_id": "r-unrecorded", "state": "delivered_unrecorded", "to": "pilot/orchestrator"},
            {"request_id": "r-revoked", "state": "routed", "revoked_after_route": True, "to": "pilot/orchestrator"},
            {"request_id": "r-routed", "state": "routed", "to": "pilot/orchestrator"}]}
    router = answering(world, "fixed-router.py", {"status": (0, status),
                                                  "route": (2, {"state": "hold", "error": "route refused"})})

    result = world.once(expect=3, swap=("router", router))

    found = {key: (row["act"], row["detail"]) for key, row in holds(result).items() if key[0] != "sweep"}
    assert found == {
        ("route", "route_refused", None): ("router", "route refused"),
        ("route", "request_held", "r-held"): ("router", json.dumps({"detail": "expired at noon",
                                                                    "reason": "approval_expired"}, sort_keys=True)),
        ("route", "delivered_unrecorded", "r-unrecorded"): ("router", "pilot/orchestrator"),
        ("route", "revoked_after_route", "r-revoked"): ("router", "pilot/orchestrator"),
        ("router_status", "escalation", "r-esc"): ("root", json.dumps({"reason": "over budget", "team": "pilot"},
                                                                      sort_keys=True)),
    }


def test_a_lost_route_report_still_raises_each_held_request(world):
    status = {"router": "router-1", "escalations": [], "requests": [{"request_id": "r1", "state": "ready"}]}
    router = answering(world, "reportless-router.py", {"status": (0, status), "route": (0, {
        "routed": [], "requests": None, "report_error": "journal busy", "held": {"r1": {"reason": "delivery_error"}}})})

    result = world.once(expect=3, swap=("router", router))

    found = {key: (row["act"], row["detail"]) for key, row in holds(result, "route").items()}
    assert found == {("route", "route_report_error", None): ("router", "journal busy"),
                     ("route", "request_held", "r1"): ("router", json.dumps({"reason": "delivery_error"}))}


def test_a_root_past_its_limit_is_a_rotate_hold_for_root(world):
    codex_transcript(world, "root-session", 90)

    result = world.once(expect=3)

    held = holds(result)[("sweep", "root_rotate", None)]
    assert held["act"] == "root" and json.loads(held["detail"])["state"] == "rotate_now"


def test_a_job_that_needs_root_is_a_hold_for_root_and_a_finished_one_is_not(world):
    jobs = answering(world, "fixed-jobs.py", {"run-open": (3, {"rows": [
        {"job": "pilot/job-1", "state": "abandoned", "pid": 7}, {"job": "pilot/job-2", "state": "completed"}]})})

    result = world.once(expect=3, swap=("jobs", jobs))

    assert {key: (row["act"], row["detail"]) for key, row in holds(result, "run_open").items()} == {
        ("run_open", "job_abandoned", "pilot/job-1"): ("root", json.dumps({"pid": 7}))}


def test_the_real_sweep_skips_an_endpoint_under_a_start_failing_hold(world):
    world.send("pilot/root", "pilot/orchestrator", "hello")
    world.state_dir.mkdir()
    world.status_path.write_text(json.dumps({
        "schema": "aegis.loop-status/v1", "pass_id": 7, "consecutive_journal_unavailable": 0, "interval": None,
        "finished_at": "2026-11-05T00:00:00Z", "steps": [], "stopped": False, "holds": [
            {"step": "sweep", "kind": "start_failing", "act": "owner", "detail": "why", "initiative": "pilot",
             "endpoint": "pilot/orchestrator", "first_seen": "2026-11-05T00:00:00Z",
             "last_seen": "2026-11-05T00:00:00Z", "count": 3}]}))

    result = world.once(expect=3)

    assert world.launches() == []
    assert set(holds(result)) == {("sweep", "start_failing", "pilot/orchestrator")}, "no skipped or still_unread hold"
    assert holds(result)[("sweep", "start_failing", "pilot/orchestrator")]["count"] == 4
    world.status_path.unlink()
    world.once()
    assert world.woken() == ["pilot/orchestrator"]


def root_lines(text):
    lines = text.splitlines()
    block = lines[lines.index("root:") + 1:]
    return block[:next((i for i, line in enumerate(block) if not line.startswith("  ")), len(block))]


def test_a_route_the_orchestrator_reads_and_leaves_unanswered_is_a_silent_role_hold_for_root_until_it_publishes(world):
    world.approved(request("feature-1", team="pilot"))
    route = "route-" + world.ledger.status()["requests"]["feature-1"]["raw"]["sha256"]

    first, second = world.once(expect=3), world.once(expect=3)

    key = ("sweep", "silent_role", "pilot/orchestrator")
    held = holds(second)[key]
    assert (held["act"], held["initiative"], held["count"]) == ("root", "pilot", 2)
    assert held["first_seen"] == holds(first)[key]["first_seen"]
    assert re.fullmatch(r"read info %s from pilot/router in wake %s \(exited with code 0 at %s\) and has published "
                        r"nothing since %s" % (route, WAKE_ID, STAMP, STAMP), held["detail"]), held["detail"]
    assert "  sweep silent_role pilot/orchestrator: %s (seen 2 times since %s)" % (
        held["detail"], held["first_seen"]) in root_lines(world.status("--text", expect=3))

    world.send("pilot/orchestrator", "pilot/root", "answer")
    answered = world.once(expect=3)

    assert key not in holds(answered)
    assert ("sweep", "root_queue", "pilot/root") in holds(answered)


def test_a_lane_that_accepts_its_dispatch_and_stops_is_a_stalled_dispatch_hold_for_root_until_it_answers(world):
    world.add_role("pilot/lane/review", cwd=str(world.tmp))
    world.plan({"pilot/lane/review": {"send": [{"message_id": "review-1-accepted", "to": "pilot/orchestrator",
                                                "type": "ack", "acknowledgment": "accepted", "in_reply_to": "review-1",
                                                "body": "Accepted."}]}})
    brief = world.base / "review-brief.md"
    brief.write_bytes(b"Review it.\n")
    world.send("pilot/orchestrator", "pilot/lane/review", "review-1", type="dispatch",
               brief={"path": str(brief), "sha256": hashlib.sha256(b"Review it.\n").hexdigest()})

    accepted = world.once(expect=3)     # the Reviewer's turn: it accepts, publishes nothing more, and ends
    again = world.once(expect=3)        # the Orchestrator reads the ack; nothing will wake the Reviewer again

    key = ("sweep", "stalled_dispatch", "pilot/lane/review")
    assert ("sweep", "silent_role", "pilot/lane/review") not in holds(accepted), "the acceptance was a publish"
    held = holds(again)[key]
    assert (held["act"], held["initiative"], held["count"]) == ("root", "pilot", 2)
    assert held["first_seen"] == holds(accepted)[key]["first_seen"]
    assert re.fullmatch(r"accepted dispatch review-1 at %s but sent no result or review; its last wake %s ended at %s "
                        r"and nothing is unread or running, so no wake will come" % (STAMP, WAKE_ID, STAMP),
                        held["detail"]), held["detail"]
    assert "  sweep stalled_dispatch pilot/lane/review: %s (seen 2 times since %s)" % (
        held["detail"], held["first_seen"]) in root_lines(world.status("--text", expect=3))

    world.send("pilot/lane/review", "pilot/orchestrator", "review-1-verdict", type="review", in_reply_to="review-1",
               result=EVIDENCE)
    answered = world.once(expect=3)

    assert key not in holds(answered)
