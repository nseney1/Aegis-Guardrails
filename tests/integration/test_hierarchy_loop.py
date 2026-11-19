"""The loop service runs the router, the durable sweep and run-open on a schedule, and reports what holds.

Every step is the real tool as a child process. The hosts are the fake host, and PATH is only the fake
binaries plus links to the tools the steps need, so no real model binary can start. These tests show the
tools work together on fixtures, not that real sessions behave this way.
"""
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
LINUX_ONLY = pytest.mark.skipif(not sys.platform.startswith("linux"),
                                reason="run-open reads /proc and wake uses POSIX process groups")


@LINUX_ONLY
@pytest.mark.parametrize("mode", ["once","run"])
@pytest.mark.parametrize("damage", ["request","plan"])
def test_round13_planning_target_error_keeps_serving_and_runs_jobs(tmp_path,mode,damage):
    from tests.integration.test_hierarchy_fresh_brief import r13_consumer_probe,R13_CONSUMER_GOLDENS
    if os.geteuid()==0: pytest.skip("mode-000 witness requires an unprivileged runner")
    seam="loop-"+mode
    assert r13_consumer_probe(tmp_path,seam,True,damage)==R13_CONSUMER_GOLDENS[(seam,True,damage)]
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


def subscription_file(world, *, budget=6):
    path = world.tmp / "subscriptions.json"
    path.write_text(json.dumps({"schema": "aegis.team-subscriptions/v1", "subscriptions": [
        {"subscriber": "pilot/root", "match": [{"type": "info", "from": "pilot/orchestrator"}],
         "budget": {"notices_per_hour": budget}}]}), encoding="utf-8")
    return path


@LINUX_ONLY
@pytest.mark.parametrize("damage,code", [
    ("missing", "SUBSCRIPTIONS_IO"), ("oversize", "SUBSCRIPTIONS_LIMIT"),
    ("json", "SUBSCRIPTIONS_INVALID"), ("entry", "SUBSCRIPTIONS_INVALID"),
    ("duplicate", "SUBSCRIPTIONS_INVALID"), ("link", "SUBSCRIPTIONS_IO"),
])
def test_subscriptions_refused_before_any_pass(world, damage, code):
    from conftest import symlink_or_skip
    config = subscription_file(world)
    if damage == "missing":
        config.unlink()
    elif damage == "oversize":
        with config.open("wb") as stream:
            stream.truncate(262145)
    elif damage == "json":
        config.write_text('{"secret=never-echo":')
    elif damage == "duplicate":
        config.write_text('{"schema":1,"schema":2}')
    elif damage == "link":
        saved = config.rename(config.with_suffix(".saved"))
        symlink_or_skip(saved, config)
    else:
        value = json.loads(config.read_text())
        value["subscriptions"][0]["subscriber"] = "pilot/front-door"
        config.write_text(json.dumps(value))
    result = json.loads(world.loop("--subscriptions", str(config), "once", expect=2))
    assert result["code"] == code
    assert "secret" not in json.dumps(result)
    assert not world.status_path.exists() and not world.launches()


@LINUX_ONLY
@pytest.mark.parametrize("value", ["0", "-1", "secret=never-echo", "1\n2"])
def test_nudge_refuses_nonpositive_before_start(world, value):
    result = json.loads(world.loop("run", "--nudge-seconds", value, "--passes", "1", expect=2))
    assert result == {"code": "SUBSCRIPTIONS_INVALID", "error": "invalid subscriptions configuration"}
    assert not world.status_path.exists()


@LINUX_ONLY
def test_nudge_large_positive_integer_never_overflows(world):
    result = json.loads(world.loop("run", "--nudge-seconds", "9" * 5000, "--passes", "1"))
    assert result["pass_id"] == 1 and result["holds"] == []


@LINUX_ONLY
@pytest.mark.parametrize("flags", [("--subscriptions",), ("run", "--nudge-seconds"),
                                    ("run", "--nudge-seconds", "-secret=never-echo")])
def test_subscription_option_syntax_errors_have_fixed_diagnostics(world, flags):
    result = json.loads(world.loop(*flags, expect=2))
    assert result == {"code": "SUBSCRIPTIONS_INVALID", "error": "invalid subscriptions configuration"}


@LINUX_ONLY
def test_notify_precedes_sweep_retries_without_duplicates_and_reports_budget(world):
    config = subscription_file(world, budget=1)
    world.publish("sub-first", "info", "Original body must never appear in a notice.")
    flags = ("--subscriptions", str(config), "once")
    first = json.loads(world.loop(*flags, expect=3))
    assert [row["step"] for row in first["steps"]] == ["router_status", "route", "notify", "sweep", "run_open"]
    assert first["subscriptions_sha256"] == hashlib.sha256(config.read_bytes()).hexdigest()
    assert first["subscription_suppressed"] == []
    notify = next(row for row in first["steps"] if row["step"] == "notify")
    assert notify["published"] == 1 and notify["state"] == "ok"
    second = json.loads(world.loop(*flags, expect=3))
    assert next(row for row in second["steps"] if row["step"] == "notify")["published"] == 0
    world.publish("sub-second", "info", "Another original body.")
    third = json.loads(world.loop(*flags, expect=3))
    assert third["subscription_suppressed"] == [
        {"initiative": "pilot", "subscriber": "pilot/root", "reason": "budget", "held": 1}]
    messages = world.inbox("pilot/root")
    notices = [row for row in messages if row["message"]["message_id"].startswith("notice-")]
    assert len(notices) == 1
    assert "Original body" not in notices[0]["message"]["body"]


@LINUX_ONLY
def test_subscriptions_ignore_unrelated_registered_mailboxes(world):
    from tests.integration.test_hierarchy_sweep import second_initiative
    other_root = second_initiative(world)
    config = subscription_file(world)
    world.publish("sub-only-pilot", "info", "Original")
    result = json.loads(world.loop("--subscriptions", str(config), "once", expect=3))
    assert next(row for row in result["steps"] if row["step"] == "notify")["published"] == 1
    assert not holds(result, "notify")
    assert not (other_root.parent / "subscriptions").exists()


@LINUX_ONLY
def test_subscriptions_partition_frozen_configuration_across_two_mailboxes(world):
    from tests.integration.test_hierarchy_provision import INITIATIVE, LANES
    base = world.tmp / "initiatives" / "second"
    provision("init", world.request(store=str(world.workspace.store), base=str(base), source=str(world.source),
                                    initiative={**INITIATIVE, "id": "second"}, lanes=LANES, roles=["router"]))
    for role in ("front-door", "orchestrator", "router"):
        provision("add-role", world.request(base=str(base), endpoint="second/" + role,
                                             host="claude-code", cwd=str(world.tmp)))
    other_root = base / "mailbox"
    config = subscription_file(world)
    value = json.loads(config.read_text())
    value["subscriptions"].append({"subscriber": "second/orchestrator", "match": [{"from": "second/front-door"}]})
    config.write_text(json.dumps(value))
    world.publish("sub-pilot", "info", "Pilot body")
    world.publish("sub-second", "info", "Second body", root=other_root,
                  sender="second/front-door", to="second/orchestrator")
    result = json.loads(world.loop("--subscriptions", str(config), "once", expect=3))
    assert next(row for row in result["steps"] if row["step"] == "notify")["published"] == 2
    assert result["subscriptions_sha256"] == hashlib.sha256(config.read_bytes()).hexdigest()
    for root, subscriber in ((world.root, "pilot/root"), (other_root, "second/orchestrator")):
        snapshot, = (root.parent / "subscriptions").glob("configuration-*.json")
        assert [entry["subscriber"] for entry in json.loads(snapshot.read_text())["subscriptions"]] == [subscriber]


@LINUX_ONLY
def test_notify_lock_failure_is_hold_and_later_steps_continue_then_recover(world):
    config = subscription_file(world)
    world.publish("sub-first", "info", "Original")
    lock = world.root / ".write.lock"
    lock.write_text("test-owned lock")
    flags = ("--subscriptions", str(config), "once")
    failed = json.loads(world.loop(*flags, expect=3))
    assert ("notify", "SUBSCRIPTIONS_MAILBOX_LOCKED", "pilot") in {
        (row["step"], row["kind"], row.get("initiative")) for row in failed["holds"]}
    assert next(row for row in failed["steps"] if row["step"] == "notify")["state"] == "hold"
    assert [row["step"] for row in failed["steps"]][-2:] == ["sweep", "run_open"]
    assert lock.read_text() == "test-owned lock"
    lock.unlink()
    recovered = json.loads(world.loop(*flags, expect=3))
    assert next(row for row in recovered["steps"] if row["step"] == "notify")["published"] == 1


@LINUX_ONLY
def test_without_subscriptions_public_entry_preserves_baseline_bytes(world):
    before = {str(path): path.read_bytes() for path in world.root.rglob("*.md")}
    raw = world.loop("once")
    value = json.loads(raw)
    for field in ("started_at", "finished_at"):
        assert re.fullmatch(STAMP, value[field])
        raw = raw.replace(value[field], "STAMP")
    expected = {"schema": "aegis.loop-status/v1", "pass_id": 1, "started_at": "STAMP", "finished_at": "STAMP",
                "interval": None, "steps": [{"step": "router_status", "state": "ok", "exit": 0, "router": "router-1"},
                    {"step": "route", "state": "skipped"},
                    {"step": "sweep", "state": "ok", "exit": 0, "woken": []},
                    {"step": "run_open", "state": "ok", "exit": 0, "rows": []}],
                "holds": [], "stopped": False, "consecutive_journal_unavailable": 0,
                "current_step": None, "step_started_at": None}
    assert raw == json.dumps(expected, sort_keys=True) + "\n"
    assert world.status_path.read_bytes() == (json.dumps(value, sort_keys=True) + "\n").encode()
    assert before == {str(path): path.read_bytes() for path in world.root.rglob("*.md")}


@LINUX_ONLY
def test_subscriptions_unsupported_probe_refuses_cleanly(world, monkeypatch, capsys):
    import hierarchy_loop
    import hierarchy_loop_subscriptions
    config = subscription_file(world)
    monkeypatch.setattr("hierarchy_loop_subscriptions.supported", lambda: False)
    assert hierarchy_loop.main([*world.flags(), "--subscriptions", str(config), "once"]) == 2
    assert json.loads(capsys.readouterr().out) == {
        "code": "SUBSCRIPTIONS_UNSUPPORTED", "error": "subscription descriptor operations unavailable"}


def probed_loop(world, source, *flags, expect):
    """Run LP's public entry with a local boundary probe, like SWAPPED above."""
    prelude = ("import sys\nfrom pathlib import Path\nfrom types import SimpleNamespace\n"
               "sys.path.insert(0, sys.argv[1])\nimport hierarchy_loop as loop\n"
               "import hierarchy_loop_subscriptions as helper\n")
    script = world.script("subscription-probe.py", prelude + source + "\nsys.exit(loop.main(sys.argv[2:]))\n")
    result = subprocess.run([sys.executable, "-I", "-B", str(script), str(LOOP.parent), *world.flags(), *flags],
                            capture_output=True, text=True, timeout=90, env=world.env())
    assert not result.stderr and result.returncode == expect, result.stdout + result.stderr
    return [json.loads(line) for line in result.stdout.splitlines()]


@LINUX_ONLY
def test_subscriptions_configuration_is_frozen_until_restart(world):
    config = subscription_file(world)
    expected_hash = hashlib.sha256(config.read_bytes()).hexdigest()
    world.publish("sub-frozen", "info", "Original")
    result, = probed_loop(world, """
original = loop.one_pass
def changed(*args, **kwargs):
    Path(sys.argv[sys.argv.index('--subscriptions') + 1]).write_text('invalid replacement')
    return original(*args, **kwargs)
loop.one_pass = changed
""", "--subscriptions", str(config), "once", expect=3)
    assert result["subscriptions_sha256"] == expected_hash
    assert next(row for row in result["steps"] if row["step"] == "notify")["published"] == 1


@pytest.mark.parametrize("change", ["mail", "none", "removed", "stop"])
def test_nudge_wait_is_stat_only_and_bounded(polling_mailbox, monkeypatch, change):
    from types import SimpleNamespace
    import hierarchy_loop_subscriptions as helper
    now, sleeps, stopped, changed = [0.0], [], [False], [False]

    def sleep(seconds):
        now[0] += seconds
        sleeps.append(seconds)
        if now[0] >= 1 and change == "mail" and not changed[0]:
            (polling_mailbox / "a" / "root" / "test-new.md").touch()
            changed[0] = True
        elif now[0] >= 1 and change == "removed" and not changed[0]:
            (polling_mailbox / "a" / "root").rename(polling_mailbox / "a" / "root-old")
            changed[0] = True
        elif change == "stop":
            stopped[0] = True

    clock = SimpleNamespace(monotonic=lambda: now[0], sleep=sleep)
    monkeypatch.setattr("hierarchy_loop_subscriptions.time", clock)
    with helper.InboxNudge([polling_mailbox]) as watcher:
        def unexpected_open(*args, **kwargs):
            pytest.fail("nudge wait must use stat calls only")
        monkeypatch.setattr("hierarchy_loop_subscriptions.os", SimpleNamespace(**{**vars(os), "open": unexpected_open}))
        watcher.wait(30, 2, lambda: stopped[0])
    assert now[0] == (30 if change == "none" else 2 if change in {"mail", "removed"} else 0.2)
    assert sleeps and max(sleeps) <= 0.2


@LINUX_ONLY
def test_notify_notice_reaches_the_existing_sweep_wake_path(world):
    config = subscription_file(world)
    value = json.loads(config.read_text())
    value["subscriptions"][0].update(subscriber="pilot/orchestrator", match=[{"from": "pilot/front-door"}])
    config.write_text(json.dumps(value))
    world.publish("sub-wake", "info", "Original", sender="pilot/front-door", to="pilot/orchestrator")
    result = json.loads(world.loop("--subscriptions", str(config), "once", expect=3))
    assert next(row for row in result["steps"] if row["step"] == "notify")["published"] == 1
    assert world.woken() == ["pilot/orchestrator"]
    assert len([row for row in world.inbox("pilot/orchestrator")
                if row["message"]["message_id"].startswith("notice-")]) == 1


@LINUX_ONLY
def test_nudge_public_run_observes_mail_arriving_during_a_pass(world):
    results = probed_loop(world, """
now = [0.0]
original = loop.one_pass
def pass_with_arrival(*args, **kwargs):
    result = original(*args, **kwargs)
    if result[2]['pass_id'] == 1:
        mailbox = helper.Mailbox(helper.active_mailboxes(args[0].store)[0]['mailbox_root'])
        binding = mailbox.current_binding('pilot/orchestrator')
        mailbox.publish({'message_id': 'sub-arrival', 'from': 'pilot/orchestrator', 'to': 'pilot/root',
                         'type': 'info', 'body': 'New mail', 'host': binding['host'],
                         'session': binding['session'], 'binding_generation': binding['generation']})
    else:
        assert now[0] == 2
    return result
def sleep(seconds):
    now[0] += seconds
loop.one_pass = pass_with_arrival
helper.time = SimpleNamespace(monotonic=lambda: now[0], sleep=sleep)
""", "run", "--interval", "30", "--passes", "2", "--nudge-seconds", "2", expect=3)
    assert [row["pass_id"] for row in results] == [1, 2]


@LINUX_ONLY
def test_notify_concurrent_loop_entries_publish_at_most_once(world):
    from concurrent.futures import ThreadPoolExecutor
    config = subscription_file(world)
    world.publish("sub-concurrent", "info", "Original")
    argv = [sys.executable, "-I", "-B", str(LOOP), *world.flags(), "--subscriptions", str(config), "once"]

    def run():
        return subprocess.run(argv, capture_output=True, text=True, timeout=90, env=world.env())

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: run(), range(2)))
    assert all(not result.stderr and result.returncode in {2, 3} for result in results)
    assert any(result.returncode == 3 for result in results)
    assert len([row for row in world.inbox("pilot/root")
                if row["message"]["message_id"].startswith("notice-")]) == 1


@LINUX_ONLY
def test_nudge_setup_failure_is_hold_and_next_pass_recovers(world):
    first, second = probed_loop(world, """
original = helper.prepare_nudge
attempts = []
def prepare(args):
    attempts.append(True)
    if len(attempts) == 1:
        return None, helper.SubscriptionError('IO')
    return original(args)
helper.prepare_nudge = prepare
""", "run", "--interval", "5", "--passes", "2", "--nudge-seconds", "1", expect=0)
    assert ("nudge", "SUBSCRIPTIONS_IO", None) in holds(first)
    assert second["holds"] == []


@LINUX_ONLY
@pytest.mark.parametrize("damage", ["ancestor", "file"])
def test_subscriptions_descriptor_read_survives_concurrent_rename(world, monkeypatch, damage):
    from contextlib import contextmanager
    from conftest import symlink_or_skip
    import hierarchy_loop_subscriptions as helper
    original = helper.confined_file
    parent = world.tmp / "config-dir"
    parent.mkdir()
    source = subscription_file(world).rename(parent / "subscriptions.json")
    expected = hashlib.sha256(source.read_bytes()).hexdigest()
    changed = []

    @contextmanager
    def swapped(root, parts, **kwargs):
        with original(root, parts, **kwargs) as target:
            if root == parent and not changed:
                changed.append(True)
                if damage == "ancestor":
                    parent.rename(world.tmp / "saved-config")
                    symlink_or_skip(world.tmp, parent, target_is_directory=True)
                else:
                    source.rename(parent / "saved.json")
                    symlink_or_skip(parent / "saved.json", source)
            yield target

    monkeypatch.setattr("hierarchy_loop_subscriptions.confined_file", swapped)
    if damage == "ancestor":
        result = helper.LoopSubscriptions(world.workspace.store, str(source))
        assert result.sha256 == expected
    else:
        with pytest.raises(helper.SubscriptionError) as caught:
            helper.LoopSubscriptions(world.workspace.store, str(source))
        assert caught.value.code == "SUBSCRIPTIONS_IO"


@pytest.mark.parametrize("failed", [False, True])
def test_nudge_closes_all_descriptors_on_success_and_partial_open_failure(polling_mailbox, monkeypatch, failed):
    import errno
    from types import SimpleNamespace
    import hierarchy_loop_subscriptions as helper
    if not helper.supported():
        pytest.skip("descriptor confinement unavailable")
    opened = []

    def open_directory(*args, **kwargs):
        if failed and len(opened) == 3:
            raise OSError(errno.EMFILE, "test-owned descriptor refusal")
        descriptor = os.open(*args, **kwargs)
        opened.append(descriptor)
        return descriptor

    monkeypatch.setattr("hierarchy_loop_subscriptions.os", SimpleNamespace(**{**vars(os), "open": open_directory}))
    if failed:
        with pytest.raises(OSError) as caught:
            helper.InboxNudge([polling_mailbox])
        assert caught.value.errno == errno.EMFILE
    else:
        with helper.InboxNudge([polling_mailbox]):
            assert opened
    for descriptor in opened:
        with pytest.raises(OSError) as caught:
            os.fstat(descriptor)
        assert caught.value.errno == errno.EBADF


@LINUX_ONLY
@pytest.mark.parametrize("damage", ["link", "mode"])
def test_notify_refuses_unsafe_state_without_writing_elsewhere(world, damage):
    from conftest import symlink_or_skip
    config = subscription_file(world)
    state = world.root.parent / "subscriptions"
    outside = world.tmp / "outside-state"
    outside.mkdir()
    if damage == "link":
        symlink_or_skip(outside, state, target_is_directory=True)
    else:
        state.mkdir(mode=0o777)
        state.chmod(0o777)
    result = json.loads(world.loop("--subscriptions", str(config), "once", expect=3))
    expected = "SUBSCRIPTIONS_PATH" if damage == "link" else "SUBSCRIPTIONS_IO"
    assert ("notify", expected, None) in holds(result)
    assert list(outside.iterdir()) == []


@pytest.fixture
def polling_mailbox(tmp_path):
    root = tmp_path.resolve() / "mailbox"
    invoke(root, "init", {"schema": "aegis.hierarchy-pilot/v1", "writer_limit": 3, "counterparts": [],
                          "endpoints": {"a/" + role: {} for role in ("front-door", "root", "router", "orchestrator")}})
    return root


@LINUX_ONLY
def test_r2_state_equal_to_mailbox_refuses_before_snapshot_write(world):
    from tests.integration.test_hierarchy_workspace import Workspace
    config = subscription_file(world)
    world.publish("placement", "info", "Original")
    root = world.root.rename(world.root.parent / "subscriptions")
    fresh = world.tmp / "placement-store"
    fresh.mkdir()
    world.workspace = Workspace(fresh)
    world.workspace.run("init", {"writer_limit": 3, "heavy_limit": 3})
    world.workspace.register("pilot", mailbox_root=str(root), delivery_dir=str(world.base / "delivery"))
    before = {path.relative_to(root): path.read_bytes() for path in root.rglob("*") if path.is_file()}
    result = json.loads(world.loop("--subscriptions", str(config), "once", expect=3))
    assert ("notify", "SUBSCRIPTIONS_PATH", None) in holds(result)
    assert before == {path.relative_to(root): path.read_bytes() for path in root.rglob("*") if path.is_file()}


@LINUX_ONLY
@pytest.mark.parametrize("flags", [
    ("--subs", "safe.json", "run", "--passes", "secret=VALUE"),
    ("run", "--nudge-s", "1", "--passes", "secret=VALUE"),
    ("--subs=safe.json", "once"), ("run", "--nudge-s=1", "--passes", "1"),
])
def test_r2_abbreviations_refuse_without_echo(world, flags):
    assert json.loads(world.loop(*flags, expect=2)) == {
        "code": "SUBSCRIPTIONS_INVALID", "error": "invalid subscriptions configuration"}


def test_r2_nudge_shares_ancestor_descriptors(polling_mailbox):
    import hierarchy_loop_subscriptions as helper
    if not helper.supported():
        pytest.skip("descriptor confinement unavailable")
    with helper.InboxNudge([polling_mailbox]) as watcher:
        identities = [(os.fstat(fd).st_dev, os.fstat(fd).st_ino) for fd in watcher.descriptors]
        assert len(identities) == len(set(identities))


@LINUX_ONLY
def test_r2_child_descriptor_pressure_holds_then_continues_and_recovers(world):
    first, second = probed_loop(world, """
import errno
original = loop.subprocess.run
original_prepare = helper.prepare_nudge
failed = []
watchers = []
def prepared(args):
    watcher, error = original_prepare(args)
    assert error is None and watcher.descriptors and not watcher.closed
    watchers.append(watcher)
    return watcher, error
def pressured(*args, **kwargs):
    if not failed:
        assert watchers and not watchers[0].closed
        failed.append(True)
        raise OSError(errno.EMFILE, 'secret=never-echo')
    assert watchers[0].closed
    return original(*args, **kwargs)
helper.prepare_nudge = prepared
loop.subprocess = SimpleNamespace(**{**vars(loop.subprocess), 'run': pressured})
""", "run", "--interval", "5", "--passes", "2", "--nudge-seconds", "1", expect=0)
    assert ("nudge", "NUDGE_LIMIT", None) in holds(first)
    assert [row["step"] for row in first["steps"]][-2:] == ["sweep", "run_open"]
    assert second["holds"] == []
    assert "secret" not in json.dumps(first)


@pytest.mark.parametrize("change", [False, True])
def test_r2_nudge_portable_stat_polling(polling_mailbox, monkeypatch, change):
    from types import SimpleNamespace
    import hierarchy_loop_subscriptions as helper
    now = [0.0]

    def sleep(seconds):
        now[0] += seconds
        if change and now[0] >= 1:
            (polling_mailbox / "a" / "root" / "new.md").touch()

    monkeypatch.setattr("hierarchy_loop_subscriptions.supported", lambda: False)
    monkeypatch.setattr("hierarchy_loop_subscriptions.time", SimpleNamespace(monotonic=lambda: now[0], sleep=sleep))
    args = SimpleNamespace(subscriptions=None, nudge_seconds="2", interval=5)
    helper.configure(args)
    with helper.InboxNudge([polling_mailbox]) as watcher:
        watcher.wait(5, args.nudge_seconds, lambda: False)
    assert now[0] == (2 if change else 5)


def test_r2_nudge_unsupported_is_typed_and_recoverable(polling_mailbox, monkeypatch):
    from types import SimpleNamespace
    import hierarchy_loop_subscriptions as helper
    monkeypatch.setattr("hierarchy_loop_subscriptions.active_mailboxes", lambda _: [{"mailbox_root": str(polling_mailbox)}])
    monkeypatch.setattr("hierarchy_loop_subscriptions.supported", lambda: False)
    monkeypatch.setattr("hierarchy_loop_subscriptions.path_polling_supported", lambda: False)
    watcher, error = helper.prepare_nudge(SimpleNamespace(store="unused"))
    assert watcher is None and error.code == "NUDGE_UNSUPPORTED"
    assert str(error) == "nudge metadata polling unavailable"
    monkeypatch.setattr("hierarchy_loop_subscriptions.path_polling_supported", lambda: True)
    watcher, error = helper.prepare_nudge(SimpleNamespace(store="unused"))
    assert error is None
    watcher.close()


def test_r2_nudge_unavailable_store_is_typed(tmp_path, monkeypatch):
    from types import SimpleNamespace
    import hierarchy_loop_subscriptions as helper
    monkeypatch.setattr("hierarchy_loop_subscriptions.supported", lambda: False)
    watcher, error = helper.prepare_nudge(SimpleNamespace(store=tmp_path / "missing-store"))
    assert watcher is None and error.code == "NUDGE_IO"
    assert str(error) == "nudge metadata I/O refused"


def test_r2_nudge_budget_exhaustion_is_typed_and_recoverable(polling_mailbox, monkeypatch):
    from types import SimpleNamespace
    import hierarchy_loop_subscriptions as helper
    if not helper.supported():
        pytest.skip("descriptor confinement unavailable")
    monkeypatch.setattr("hierarchy_loop_subscriptions.active_mailboxes", lambda _: [{"mailbox_root": str(polling_mailbox)}])
    monkeypatch.setattr("hierarchy_loop_subscriptions.descriptor_capacity", lambda: 0)
    watcher, error = helper.prepare_nudge(SimpleNamespace(store="unused"))
    assert watcher is None and error.code == "NUDGE_LIMIT"
    monkeypatch.setattr("hierarchy_loop_subscriptions.descriptor_capacity", lambda: 64)
    watcher, error = helper.prepare_nudge(SimpleNamespace(store="unused"))
    assert error is None
    watcher.close()


@LINUX_ONLY
def test_r2_partial_notify_marks_totals_and_suppression_unknown(world):
    manifest = world.root / "manifest.json"
    value = json.loads(manifest.read_text())
    value["endpoints"].update({"b/" + role: {} for role in ("front-door", "root", "router", "orchestrator")})
    manifest.write_text(json.dumps(value))
    for role in ("front-door", "root", "router", "orchestrator"):
        (world.root / "b" / role).mkdir(parents=True, exist_ok=True)
    invoke(world.root, "bind", {"endpoint": "b/orchestrator", "host": "host-one", "session": "b-orch", "expected_generation": 0})
    invoke(world.root, "bind", {"endpoint": "b/root", "host": "host-one", "session": "b-root", "expected_generation": 0})
    world.publish("partial-first", "info", "Original")
    world.publish("partial-second", "info", "Original", sender="b/orchestrator", to="b/root")
    config = subscription_file(world, budget=1)
    value = json.loads(config.read_text())
    value["subscriptions"].append({"subscriber": "b/root", "match": [{"from": "b/orchestrator"}]})
    config.write_text(json.dumps(value))
    result = json.loads(world.loop("--subscriptions", str(config), "once", expect=3))
    step = next(row for row in result["steps"] if row["step"] == "notify")
    assert step["published"] is None and step["complete"] is False
    assert result["subscription_suppressed_complete"] is False
    assert len([row for row in world.inbox("pilot/root") if row["message"]["message_id"].startswith("notice-")]) == 1
    world.publish("partial-held", "info", "Queued while second subscriber fails")
    incomplete = json.loads(world.loop("--subscriptions", str(config), "once", expect=3))
    assert incomplete["subscription_suppressed_complete"] is False
    invoke(world.root, "bind", {"endpoint": "b/router", "host": "host-one", "session": "b-router", "expected_generation": 0})
    recovered = json.loads(world.loop("--subscriptions", str(config), "once", expect=3))
    step = next(row for row in recovered["steps"] if row["step"] == "notify")
    assert step["complete"] is True and step["published"] == 1
    assert recovered["subscription_suppressed_complete"] is True
    assert recovered["subscription_suppressed"] == [
        {"initiative": "pilot", "subscriber": "pilot/root", "reason": "budget", "held": 1}]
    assert len([row for row in world.inbox("pilot/root") if row["message"]["message_id"].startswith("notice-")]) == 1


@LINUX_ONLY
@pytest.mark.parametrize("empty", [False, True])
@pytest.mark.parametrize("paused", [False, True])
def test_r4_state_overlap_with_unselected_mailbox_refuses_before_any_write(world, empty, paused):
    from concurrent.futures import ThreadPoolExecutor
    from tests.integration.test_hierarchy_sweep import second_initiative
    from tests.integration.test_hierarchy_workspace import Workspace
    config = subscription_file(world)
    if empty:
        config.write_text(json.dumps({"schema": "aegis.team-subscriptions/v1", "subscriptions": []}))
    other = second_initiative(world).rename(world.root.parent / "subscriptions")
    fresh = world.tmp / "overlap-store"
    fresh.mkdir()
    world.workspace = Workspace(fresh)
    world.workspace.run("init", {"writer_limit": 3, "heavy_limit": 3})
    world.workspace.register("pilot", mailbox_root=str(world.root), delivery_dir=str(world.base / "delivery"))
    world.workspace.register("second", mailbox_root=str(other), delivery_dir=str(world.tmp / "second-delivery"))
    if paused:
        world.workspace.run("update", {"initiative": "second", "source": "owner", "state": "paused"})
    before = {path.relative_to(other): path.read_bytes() for path in other.rglob("*") if path.is_file()}
    for _ in range(2):
        result = json.loads(world.loop("--subscriptions", str(config), "once", expect=3))
        assert ("notify", "SUBSCRIPTIONS_PATH", None) in holds(result)
        assert [row["step"] for row in result["steps"]][-2:] == ["sweep", "run_open"]
        assert before == {path.relative_to(other): path.read_bytes() for path in other.rglob("*") if path.is_file()}
    argv = [sys.executable, "-I", "-B", str(LOOP), *world.flags(), "--subscriptions", str(config), "once"]

    def run(_):
        return subprocess.run(argv, capture_output=True, text=True, timeout=90, env=world.env())

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(run, range(2)))
    assert all(not result.stderr and result.returncode in {2, 3} for result in results)
    assert any(result.returncode == 3 for result in results)
    assert before == {path.relative_to(other): path.read_bytes() for path in other.rglob("*") if path.is_file()}

    other = other.rename(other.with_name("other-mailbox"))
    recovered_store = world.tmp / "recovered-store"
    recovered_store.mkdir()
    world.workspace = Workspace(recovered_store)
    world.workspace.run("init", {"writer_limit": 3, "heavy_limit": 3})
    world.workspace.register("pilot", mailbox_root=str(world.root), delivery_dir=str(world.base / "delivery"))
    world.workspace.register("second", mailbox_root=str(other), delivery_dir=str(world.tmp / "second-delivery"))
    recovered = json.loads(world.loop("--subscriptions", str(config), "once"))
    assert not holds(recovered, "notify")
    assert recovered["subscription_suppressed_complete"] is True
    assert before == {path.relative_to(other): path.read_bytes() for path in other.rglob("*") if path.is_file()}


def test_r4_discovery_without_o_path_uses_store_portable_reader(tmp_path, polling_mailbox, monkeypatch):
    from types import SimpleNamespace
    import hierarchy_loop_subscriptions as helper
    from tests.integration.test_hierarchy_workspace import Workspace
    workspace = Workspace(tmp_path)
    workspace.run("init", {"writer_limit": 3, "heavy_limit": 3})
    workspace.register("a", mailbox_root=str(polling_mailbox), delivery_dir=str(tmp_path / "delivery"))
    portable_os = SimpleNamespace(**{**vars(os)})
    if hasattr(portable_os, "O_PATH"):
        del portable_os.O_PATH
    monkeypatch.setattr("hierarchy_loop_subscriptions.os", portable_os)
    monkeypatch.setattr("hierarchy_workspace.os", portable_os)
    monkeypatch.setattr("hierarchy_loop_subscriptions.supported", lambda: False)
    assert [row["id"] for row in helper.active_mailboxes(workspace.store)] == ["a"]
    watcher, error = helper.prepare_nudge(SimpleNamespace(store=workspace.store))
    assert error is None
    with watcher:
        assert not watcher.descriptors


@LINUX_ONLY
def test_r4_notify_without_o_path_keeps_subscription_discovery(world):
    config = subscription_file(world)
    world.publish("no-o-path", "info", "Original")
    result, = probed_loop(world, """
import os
import hierarchy_workspace as workspace_module
portable_os = SimpleNamespace(**{**vars(os)})
if hasattr(portable_os, 'O_PATH'):
    del portable_os.O_PATH
helper.os = workspace_module.os = portable_os
""", "--subscriptions", str(config), "once", expect=3)
    assert not holds(result, "notify")
    assert next(row for row in result["steps"] if row["step"] == "notify")["published"] == 1


@LINUX_ONLY
@pytest.mark.parametrize("failed", [False, True])
def test_r4_later_step_heartbeats_report_current_notify_suppression(world, failed):
    config = subscription_file(world, budget=1)
    world.publish("heartbeat-first", "info", "Original")
    world.loop("--subscriptions", str(config), "once", expect=3)
    world.publish("heartbeat-held", "info", "Queued")
    lock = world.root / ".write.lock"
    if failed:
        lock.write_text("test-owned lock")
    log = world.tmp / "heartbeats.jsonl"
    tools = {}
    for kind, summary in (("sweep", EMPTY_SWEEP), ("jobs", {"rows": []})):
        tools[kind] = world.script("heartbeat-" + kind + ".py", (
            "import json\nfrom pathlib import Path\n"
            "with Path(%r).open('a', encoding='utf-8') as stream:\n"
            "    stream.write(Path(%r).read_text(encoding='utf-8').strip() + '\\n')\n"
            "print(json.dumps(%r))\n") % (str(log), str(world.status_path), summary))
    source = "loop.TOOLS.update(sweep=Path(%r), jobs=Path(%r))" % (str(tools["sweep"]), str(tools["jobs"]))

    def run(expect):
        result, = probed_loop(world, source, "--subscriptions", str(config), "once", expect=expect)
        beats = [json.loads(line) for line in log.read_text().splitlines()][-2:]
        assert [beat["current_step"] for beat in beats] == ["sweep", "run_open"]
        for beat in beats:
            assert beat["subscription_suppressed"] == result["subscription_suppressed"]
            assert beat["subscription_suppressed_complete"] == result["subscription_suppressed_complete"]
        return result

    result = run(3 if failed else 0)
    assert result["subscription_suppressed_complete"] is (not failed)
    if failed:
        lock.unlink()
        result = run(0)
        assert result["subscription_suppressed_complete"] is True
    assert result["subscription_suppressed"] == [
        {"initiative": "pilot", "subscriber": "pilot/root", "reason": "budget", "held": 1}]


@pytest.mark.parametrize("reason", ["EMFILE", "ENFILE", "EACCES"])
def test_r4_descriptor_capacity_maps_exhaustion_and_preserves_other_refusals(monkeypatch, reason):
    import errno
    from types import SimpleNamespace
    import hierarchy_loop_subscriptions as helper
    pytest.importorskip("resource", reason="descriptor limits require POSIX resource support")

    def unavailable(*args, **kwargs):
        raise OSError(getattr(errno, reason), "secret=never-echo")

    monkeypatch.setattr("hierarchy_loop_subscriptions.os", SimpleNamespace(**{**vars(os), "scandir": unavailable}))
    with pytest.raises(helper.NudgeError) as caught:
        helper.descriptor_capacity()
    assert caught.value.code == ("NUDGE_UNSUPPORTED" if reason == "EACCES" else "NUDGE_LIMIT")
    assert "secret" not in str(caught.value)
    monkeypatch.setattr("hierarchy_loop_subscriptions.os", os)
    assert 0 <= helper.descriptor_capacity() <= helper.MAX_NUDGE_DESCRIPTORS


@pytest.mark.parametrize("reason", ["EMFILE", "ENFILE", "EIO"])
def test_r4_nudge_open_failure_is_typed_closes_descriptors_and_recovers(polling_mailbox, monkeypatch, reason):
    import errno
    from types import SimpleNamespace
    import hierarchy_loop_subscriptions as helper
    if not helper.supported():
        pytest.skip("descriptor confinement unavailable")
    opened = []

    def open_directory(*args, **kwargs):
        if len(opened) == 3:
            raise OSError(getattr(errno, reason), "secret=never-echo")
        descriptor = os.open(*args, **kwargs)
        opened.append(descriptor)
        return descriptor

    monkeypatch.setattr("hierarchy_loop_subscriptions.active_mailboxes", lambda _: [{"mailbox_root": str(polling_mailbox)}])
    monkeypatch.setattr("hierarchy_loop_subscriptions.os", SimpleNamespace(**{**vars(os), "open": open_directory}))
    args = SimpleNamespace(store="unused")
    watcher, error = helper.prepare_nudge(args)
    assert watcher is None and error.code == ("NUDGE_IO" if reason == "EIO" else "NUDGE_LIMIT")
    assert "secret" not in str(error)
    for descriptor in opened:
        with pytest.raises(OSError) as caught:
            os.fstat(descriptor)
        assert caught.value.errno == errno.EBADF
    monkeypatch.setattr("hierarchy_loop_subscriptions.os", os)
    watcher, error = helper.prepare_nudge(args)
    assert error is None
    watcher.close()


@pytest.mark.parametrize("reader", ["descriptor", "portable"])
@pytest.mark.parametrize("stage", ["registry", "directory", "enumeration", "file", "watcher"])
@pytest.mark.parametrize("reason", ["EMFILE", "ENFILE", "EIO"])
def test_r4b_real_registry_nudge_exhaustion_recovers(tmp_path, polling_mailbox, monkeypatch, reader, stage, reason):
    from concurrent.futures import ThreadPoolExecutor
    import errno
    from types import SimpleNamespace
    import hierarchy_loop_subscriptions as helper
    import hierarchy_workspace as registry
    from tests.integration.test_hierarchy_workspace import Workspace
    if reader == "descriptor" and not registry._memo_supported():
        pytest.skip("descriptor registry replay unavailable")
    if stage == "watcher" and not helper.supported():
        pytest.skip("descriptor watcher unavailable")
    workspace = Workspace(tmp_path)
    workspace.run("init", {"writer_limit": 3, "heavy_limit": 3})
    workspace.register("a", mailbox_root=str(polling_mailbox), delivery_dir=str(tmp_path / "delivery"))
    events = workspace.store / "events"
    enabled, hits, opened, watcher_opened = [True], [], [], []

    def refuse(at):
        if enabled[0] and stage == at:
            hits.append(at)
            raise OSError(getattr(errno, reason), "secret=never-echo")

    class RegistryPath(type(polling_mailbox)):
        def stat(self, *args, **kwargs):
            if self == events and kwargs.get("follow_symlinks", True):
                refuse("registry")
            return super().stat(*args, **kwargs)

        def iterdir(self):
            if self == events:
                refuse("directory")
            for path in super().iterdir():
                if self == events:
                    refuse("enumeration")
                yield path

        def open(self, *args, **kwargs):
            if self.parent == events:
                refuse("file")
            stream = super().open(*args, **kwargs)
            opened.append(stream.fileno())
            return stream

    def registry_open(path, *args, **kwargs):
        if path == "events":
            refuse("directory")
        elif str(path).endswith(".json"):
            refuse("file")
        descriptor = os.open(path, *args, **kwargs)
        opened.append(descriptor)
        return descriptor

    def registry_scandir(path):
        refuse("enumeration")
        return os.scandir(path)

    def watcher_open(*args, **kwargs):
        if len(watcher_opened) >= 3:
            refuse("watcher")
        descriptor = os.open(*args, **kwargs)
        opened.append(descriptor)
        watcher_opened.append(descriptor)
        return descriptor

    monkeypatch.setattr("hierarchy_mailbox.Path", RegistryPath)
    monkeypatch.setattr("hierarchy_workspace._memo_supported", lambda: reader == "descriptor")
    monkeypatch.setattr("hierarchy_workspace.os", SimpleNamespace(**{**vars(os), "open": registry_open,
                                                                  "scandir": registry_scandir}))
    monkeypatch.setattr("hierarchy_loop_subscriptions.os", SimpleNamespace(**{**vars(os), "open": watcher_open}))
    if stage != "watcher":
        monkeypatch.setattr("hierarchy_loop_subscriptions.supported", lambda: False)
    args = SimpleNamespace(store=workspace.store)

    def refused(_):
        watcher, error = helper.prepare_nudge(args)
        assert watcher is None and error.code == ("NUDGE_IO" if reason == "EIO" else "NUDGE_LIMIT")
        assert str(error) == ("nudge metadata I/O refused" if reason == "EIO"
                              else "nudge descriptor or metadata budget exhausted")

    refused(None)
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(refused, range(2)))
    assert hits == [stage] * 3
    for descriptor in set(opened):
        with pytest.raises(OSError) as caught:
            os.fstat(descriptor)
        assert caught.value.errno == errno.EBADF
    enabled[0] = False
    watcher, error = helper.prepare_nudge(args)
    assert error is None
    with watcher:
        assert watcher.snapshot() == watcher.baseline
    for descriptor in set(opened):
        with pytest.raises(OSError) as caught:
            os.fstat(descriptor)
        assert caught.value.errno == errno.EBADF


@pytest.mark.parametrize("links", ["cause", "context", "branched", "cycle", "cycle_without_exhaustion"])
@pytest.mark.parametrize("reason", ["EMFILE", "ENFILE", "EIO"])
def test_r4b_registry_refusal_chain_is_classified_before_io(tmp_path, polling_mailbox, monkeypatch, links, reason):
    import errno
    from types import SimpleNamespace
    import hierarchy_loop_subscriptions as helper
    from tests.integration.test_hierarchy_workspace import Workspace
    workspace = Workspace(tmp_path)
    workspace.run("init", {"writer_limit": 3, "heavy_limit": 3})
    workspace.register("a", mailbox_root=str(polling_mailbox), delivery_dir=str(tmp_path / "delivery"))
    enabled, hits = [True], []
    wrapper = OSError(errno.EIO, "secret=wrapped")
    failure = OSError(getattr(errno, reason), "secret=never-echo")
    if links == "cause":
        wrapper.__cause__ = failure
    elif links == "context":
        wrapper.__context__ = failure
    else:
        wrapper.__cause__ = ValueError("unrelated branch")
        if links != "cycle_without_exhaustion":
            wrapper.__context__ = failure
        if links in {"cycle", "cycle_without_exhaustion"}:
            wrapper.__cause__.__context__ = wrapper

    class RegistryPath(type(polling_mailbox)):
        def stat(self, *args, **kwargs):
            if self == workspace.store / "events" and kwargs.get("follow_symlinks", True) and enabled[0]:
                hits.append(True)
                raise wrapper from wrapper.__cause__
            return super().stat(*args, **kwargs)

    monkeypatch.setattr("hierarchy_mailbox.Path", RegistryPath)
    monkeypatch.setattr("hierarchy_loop_subscriptions.supported", lambda: False)
    for _ in range(2):
        watcher, error = helper.prepare_nudge(SimpleNamespace(store=workspace.store))
        assert watcher is None
        assert error.code == ("NUDGE_LIMIT" if reason != "EIO" and links != "cycle_without_exhaustion" else "NUDGE_IO")
        assert "secret" not in str(error)
    assert len(hits) == 2
    enabled[0] = False
    watcher, error = helper.prepare_nudge(SimpleNamespace(store=workspace.store))
    assert error is None
    watcher.close()


@LINUX_ONLY
@pytest.mark.parametrize("exit_code", [0, 2, 3, 7])
@pytest.mark.parametrize("planned", [True, None])
def test_hostenv_run_child_actual_environment(tmp_path, monkeypatch, exit_code, planned):
    from types import SimpleNamespace
    import hierarchy_hosts
    import hierarchy_loop

    names, billing = set(), set()
    for host in hierarchy_hosts.describe()["hosts"].values():
        names.add(host["session_variable"]["name"])
        names.update(host["session_markers"]["names"])
        names.update(prefix + "FUTURE_MARKER" for prefix in host["session_markers"]["prefixes"])
        billing.update(host["billing_variables"])
    names.update({"CLAUDECODE", "CLAUDE_PID", "CLAUDE_CODE_SESSION_ID", "CLAUDE_CODE_MESSAGING_TOKEN",
                  "CLAUDE_EFFORT"})
    parent_before = dict(os.environ)
    environment = {**os.environ, **dict.fromkeys(names | billing, "modelled-value")}
    monkeypatch.setattr("hierarchy_loop.os", SimpleNamespace(**{**vars(os), "environ": environment}))
    script = tmp_path / "environment.py"
    script.write_text("import json, os, sys\nprint(json.dumps({'error': 'modelled refusal', "
                      "'names': sorted(os.environ)}))\nsys.exit(int(sys.argv[1]))\n", encoding="utf-8")
    monkeypatch.setattr("hierarchy_loop.TOOLS", {**hierarchy_loop.TOOLS, "router": script})
    before = dict(environment)
    expected = hierarchy_hosts.child_environment(before, "host-cli")
    for _ in range(2):
        code, result, stderr, problem = hierarchy_loop.run_child("router", [str(exit_code)], lambda value: None,
                                                                planned=planned)
        assert code == exit_code and not stderr and problem is None
        assert not names.intersection(result["names"])
        assert set(result["names"]) == set(expected)
        assert "PATH" in result["names"]
        assert {"OPENAI_API_KEY", "CODEX_API_KEY", "ANTHROPIC_API_KEY"} <= set(result["names"])
    assert environment == before and dict(os.environ) == parent_before


@LINUX_ONLY
def test_hostenv_no_plan_run_child_preserves_pre_hostenv_environment(tmp_path, monkeypatch):
    from types import SimpleNamespace
    import hierarchy_loop

    # Expected data from integration tip 2103cf22, inlined so snapshots need no repository history.
    markers = {"CODEX_CI", "CODEX_SESSION_ID", "CODEX_THREAD_ID", "CLAUDE_EFFORT", "CLAUDECODE", "CLAUDE_PID",
               "CLAUDE_CODE_SESSION_ID", "CLAUDE_CODE_MESSAGING_TOKEN", "CLAUDE_CODE_FUTURE_MARKER"}
    parent_before = dict(os.environ)
    environment = {**os.environ, **dict.fromkeys(markers, "modelled-value")}
    monkeypatch.setattr("hierarchy_loop.os", SimpleNamespace(**{**vars(os), "environ": environment}))
    script = tmp_path / "legacy-environment.py"
    script.write_text("import json, os\nprint(json.dumps({'names': sorted(os.environ)}))\n", encoding="utf-8")
    monkeypatch.setattr("hierarchy_loop.TOOLS", {**hierarchy_loop.TOOLS, "router": script})
    before = dict(environment)
    removed = {name for name in before if name in {"CLAUDECODE", "CLAUDE_PID"} or name.startswith("CLAUDE_CODE_")}
    for _ in range(2):
        code, result, stderr, problem = hierarchy_loop.run_child("router", [], lambda value: None, planned=False)
        assert (code, stderr, problem) == (0, "", None)
        assert set(result["names"]) == set(before) - removed
        assert {"CODEX_CI", "CODEX_SESSION_ID", "CODEX_THREAD_ID", "CLAUDE_EFFORT", "PATH"} <= set(result["names"])
    assert environment == before and dict(os.environ) == parent_before


@LINUX_ONLY
@pytest.mark.parametrize("plan_state", ["absent", "present", "unreadable"])
def test_hostenv_loop_reuses_dispatcher_plan_opt_in(tmp_path, monkeypatch, plan_state):
    from types import SimpleNamespace
    import hierarchy_loop

    markers = ("CODEX_CI", "CODEX_SESSION_ID", "CODEX_THREAD_ID", "CLAUDE_EFFORT", "CLAUDE_CODE_MESSAGING_TOKEN")
    environment = {**os.environ, **dict.fromkeys(markers, "modelled-value")}
    monkeypatch.setattr("hierarchy_loop.os", SimpleNamespace(**{**vars(os), "environ": environment}))
    script = tmp_path / "router.py"
    script.write_text("import json, os\nprint(json.dumps({'router': 'router-1', 'requests': [], "
                      "'names': sorted(os.environ)}))\n", encoding="utf-8")
    monkeypatch.setattr("hierarchy_loop.TOOLS", {**hierarchy_loop.TOOLS, "router": script})
    plan = tmp_path / "host-plan.json"
    if plan_state == "present":
        plan.write_text("{}", encoding="utf-8")
    elif plan_state == "unreadable":
        plan.mkdir()  # A directory cannot be read as a JSON plan on any platform.
    args = SimpleNamespace(lifecycle=tmp_path / "journal", store=tmp_path / "store", recipes=tmp_path / "recipes",
                           dispatcher_host_plan=None if plan_state == "absent" else plan)
    for _ in range(2):
        result = hierarchy_loop.Pass(args).router_status()
        assert result is not None
        retained = {"CODEX_CI", "CODEX_SESSION_ID", "CODEX_THREAD_ID", "CLAUDE_EFFORT"}
        assert retained.intersection(result["names"]) == (retained if plan_state == "absent" else set())
        assert "CLAUDE_CODE_MESSAGING_TOKEN" not in result["names"] and "PATH" in result["names"]


@LINUX_ONLY
def test_hostenv_concurrent_children_keep_plan_selection_local(tmp_path, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from types import SimpleNamespace
    import hierarchy_loop

    parent_before = dict(os.environ)
    environment = {**os.environ, "CODEX_CI": "modelled-value", "CLAUDE_EFFORT": "modelled-value"}
    monkeypatch.setattr("hierarchy_loop.os", SimpleNamespace(**{**vars(os), "environ": environment}))
    script = tmp_path / "environment.py"
    script.write_text("import json, os\nprint(json.dumps({'names': sorted(os.environ)}))\n", encoding="utf-8")
    monkeypatch.setattr("hierarchy_loop.TOOLS", {**hierarchy_loop.TOOLS, "router": script})
    before = dict(environment)
    modes = [False, True, None] * 3
    def run(planned):
        code, result, stderr, problem = hierarchy_loop.run_child("router", [], lambda value: None, planned=planned)
        assert (code, stderr, problem) == (0, "", None)
        return set(result["names"])
    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(run, modes))
    for planned, names in zip(modes, results):
        assert ("CODEX_CI" in names) == (planned is False)
        assert ("CLAUDE_EFFORT" in names) == (planned is False)
        assert "PATH" in names
    assert environment == before and dict(os.environ) == parent_before


@pytest.fixture
def world(tmp_path):
    return World(tmp_path)


@LINUX_ONLY
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


@LINUX_ONLY
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


@LINUX_ONLY
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


@LINUX_ONLY
def test_a_second_instance_is_refused_while_the_first_holds_either_lock(world):
    import fcntl

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


@LINUX_ONLY
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


@LINUX_ONLY
def test_after_router_rotation_the_new_current_router_routes(tmp_path):
    world = World(tmp_path, router_policy(tmp_path))
    checkpoint = world.ledger.cli("checkpoint")["sha256"]
    world.ledger.event("succeed", actor="router-2", predecessor="router-1", checkpoint_sha256=checkpoint)
    world.approved(request("feature-1", team="pilot"))

    result = world.once(expect=3)   # the fake Orchestrator leaves the route unanswered: a silent_role hold

    route = next(row for row in result["steps"] if row["step"] == "route")
    assert (route["actor"], route["routed"]) == ("router-2", ["feature-1"])
    assert world.ledger.status()["requests"]["feature-1"]["routed"]["actor"] == "router-2"


@LINUX_ONLY
def test_root_is_never_woken_and_its_queue_is_reported_for_root(world):
    world.send("pilot/orchestrator", "pilot/root", "for-root")

    result = world.once(expect=3)

    queue = holds(result)[("sweep", "root_queue", "pilot/root")]
    assert (queue["act"], queue["initiative"]) == ("root", "pilot")
    assert world.launches() == []


@LINUX_ONLY
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


@LINUX_ONLY
def test_status_reads_not_running_stale_and_running(world):
    import fcntl

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


@LINUX_ONLY
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


@LINUX_ONLY
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


@LINUX_ONLY
def test_a_step_killed_mid_pass_is_a_hold_and_the_pass_continues(world):
    killed = world.script("killed.py", "import os, signal\nos.kill(os.getpid(), signal.SIGKILL)\n")

    result = world.once(expect=3, swap=("sweep", killed))

    held = holds(result)[("sweep", "child_failed", None)]
    assert (held["act"], held["detail"]) == ("owner", "killed by signal 9")
    assert step_states(result) == {"router_status": "ok", "route": "skipped", "sweep": "failed", "run_open": "ok"}
    assert json.loads(world.status_path.read_text()) == result


@LINUX_ONLY
@pytest.mark.parametrize("args, error", [
    (["run", "--interval", "4"], "--interval must be between 5 and 600 seconds"),
    (["run", "--interval", "601"], "--interval must be between 5 and 600 seconds"),
    (["run", "--passes", "0"], "--passes must be a positive integer"),
    (["--max-jobs", "0", "once"], "--max-jobs must be a positive integer"),
])
def test_bad_arguments_are_refused(world, args, error):
    assert json.loads(world.loop(*args, expect=2)) == {"error": error}
    assert not world.status_path.exists()


@LINUX_ONLY
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


@LINUX_ONLY
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


@LINUX_ONLY
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


@LINUX_ONLY
def test_a_router_status_refusal_from_neither_journal_nor_store_is_a_router_status_error(world):
    refusing = answering(world, "refusing-router.py", {"status": (2, {"state": "hold", "error": "policy refused"})})

    passes = [world.once(expect=3, swap=("router", refusing)) for _ in range(3)]

    held = holds(passes[-1], "router_status")
    assert set(held) == {("router_status", "router_status_error", None)}
    assert (held[("router_status", "router_status_error", None)]["act"],
            held[("router_status", "router_status_error", None)]["detail"]) == ("root", "policy refused")
    assert [result["consecutive_journal_unavailable"] for result in passes] == [0, 0, 0]


@LINUX_ONLY
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


@LINUX_ONLY
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


@LINUX_ONLY
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


@LINUX_ONLY
def test_a_status_file_that_cannot_be_written_is_reported_and_the_loop_goes_on(world):
    world.status_path.mkdir(parents=True)

    out = world.loop("run", "--interval", "5", "--passes", "2")

    first, second = [json.loads(line) for line in out.splitlines()]
    for result in (first, second):
        assert result["status_write_error"].startswith("[Errno 21] Is a directory")
    assert (first["pass_id"], second["pass_id"]) == (1, 2), "the counts carry on in memory"
    assert ("loop", "status_reset", None) in holds(first) and second["holds"] == []
    assert world.status_path.is_dir() and list(world.state_dir.iterdir()) == [world.status_path]


@LINUX_ONLY
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


@LINUX_ONLY
def test_a_status_probes_shared_lock_does_not_refuse_a_starting_loop(world):
    world.lock_path("lifecycle").touch(mode=0o600)

    proc = subprocess.run([sys.executable, "-I", "-B", "-c", PROBED, str(LOOP), str(world.lock_path("lifecycle")),
                           *world.flags(), "once"], capture_output=True, text=True, timeout=60, env=world.env())

    assert proc.returncode == 0 and not proc.stderr, proc.stdout + proc.stderr
    assert json.loads(proc.stdout.splitlines()[-1])["pass_id"] == 1


@LINUX_ONLY
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


@LINUX_ONLY
def test_a_lock_path_that_is_not_a_regular_file_is_refused(world):
    os.mkfifo(world.lock_path("store"))

    assert json.loads(world.loop("once", expect=2)) == {
        "error": "loop lock is not a regular file: " + str(world.lock_path("store"))}
    assert not world.status_path.exists()


@LINUX_ONLY
def test_router_request_rows_and_unresolved_escalations_become_holds(world):
    status = {"router": "router-1", "escalations": [
        {"request_id": "r-esc", "reason": "over budget", "team": "pilot", "root_decision": None},
        {"request_id": "r-decided", "reason": "over budget", "team": "pilot", "root_decision": "deny"}],
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


@LINUX_ONLY
def test_a_lost_route_report_still_raises_each_held_request(world):
    status = {"router": "router-1", "escalations": [], "requests": [{"request_id": "r1", "state": "ready"}]}
    router = answering(world, "reportless-router.py", {"status": (0, status), "route": (0, {
        "routed": [], "requests": None, "report_error": "journal busy", "held": {"r1": {"reason": "delivery_error"}}})})

    result = world.once(expect=3, swap=("router", router))

    found = {key: (row["act"], row["detail"]) for key, row in holds(result, "route").items()}
    assert found == {("route", "route_report_error", None): ("router", "journal busy"),
                     ("route", "request_held", "r1"): ("router", json.dumps({"reason": "delivery_error"}))}


@LINUX_ONLY
def test_a_root_past_its_limit_is_a_rotate_hold_for_root(world):
    codex_transcript(world, "root-session", 90)

    result = world.once(expect=3)

    held = holds(result)[("sweep", "root_rotate", None)]
    assert held["act"] == "root" and json.loads(held["detail"])["state"] == "rotate_now"


@LINUX_ONLY
def test_a_job_that_needs_root_is_a_hold_for_root_and_a_finished_one_is_not(world):
    jobs = answering(world, "fixed-jobs.py", {"run-open": (3, {"rows": [
        {"job": "pilot/job-1", "state": "abandoned", "pid": 7}, {"job": "pilot/job-2", "state": "completed"}]})})

    result = world.once(expect=3, swap=("jobs", jobs))

    assert {key: (row["act"], row["detail"]) for key, row in holds(result, "run_open").items()} == {
        ("run_open", "job_abandoned", "pilot/job-1"): ("root", json.dumps({"pid": 7}))}


@LINUX_ONLY
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


@LINUX_ONLY
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


@LINUX_ONLY
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
    # The Orchestrator answers the verdict, so whether its dispatch falls inside a turn's 5 s slack cannot decide
    # a silent_role hold; ROOT's unread copy keeps this pass on hold.
    world.plan({"pilot/orchestrator": {"send": [{"message_id": "reviewed", "to": "pilot/root", "type": "info",
                                                 "body": "Reviewed."}]}})
    answered = world.once(expect=3)

    assert key not in holds(answered)
    assert set(holds(answered)) == {("sweep", "root_queue", "pilot/root")}
