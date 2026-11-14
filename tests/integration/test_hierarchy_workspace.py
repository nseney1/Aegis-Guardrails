"""The workspace controller coordinates initiatives, shared capacity and leases across clones.

Git repositories and Aegis leases here are real. Initiative labels are fixtures: nothing
in this file observes a host session, and a simulated run proves no host behavior.
"""
import errno
import hashlib
import json
import os
from pathlib import Path
import random
import re
import shutil
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
import venv

import pytest

from tools import hierarchy_workspace as controller
from aegis_core import team as lease_reader
from aegis_core.redaction import SECRET_REPLACEMENTS, redact_command_secrets
from tests.integration.test_hierarchy_mailbox import ROOT, git, invoke, message
from tests.integration.test_hierarchy_scenario import aegis


CONTROLLER = ROOT / "tools" / "hierarchy_workspace.py"
COMMIT = "a" * 40
LATER_COMMIT = "b" * 40
FIXED_REFUSAL = {"error": "WORKSPACE_REFUSED", "next_action": "inspect the workspace inputs and retry"}


def fingerprint(value):
    raw = value if isinstance(value, bytes) else value.encode("utf-8", errors="surrogatepass")
    return "<redacted len=%d sha256=%s>" % (len(value), hashlib.sha256(raw).hexdigest()[:12])


def claim_path_refusal(workspace, paths):
    # Invalid paths are refused by the real public claim before repository I/O.
    with pytest.raises(lease_reader.TeamUsageError) as error:
        lease_reader.claim(workspace.tmp, "candidate", paths)
    return str(error.value)


@pytest.mark.parametrize("kind", controller.KINDS)
def test_request_replay_has_linear_request_visits(kind):
    class CountedRequests(dict):
        visits = 0

        def values(self):
            for row in super().values():
                self.visits += 1
                yield row

    ledger = controller.Ledger()
    ledger.requests = CountedRequests()

    def apply(kind, data, schema=controller.EVENT_SCHEMA):
        ledger.apply({"schema": schema, "seq": ledger.seq + 1, "at": "2026-11-10T00:00:00Z",
                      "kind": kind, "data": data})

    apply("init", {"writer_limit": 3, "heavy_limit": 1})
    apply("register", {"id": "a1", "project": "aegis", "repository": "aegis", "priority": 1,
                       "target_branch": "develop"})
    for index in range(40):
        old, new = "req-%08d" % (index * 2), "req-%08d" % (index * 2 + 1)
        body = {"initiative": "a1", "kind": kind, "holder": "same"}
        apply("request", {**body, "request_id": old})
        with pytest.raises(ValueError, match="^holder already has an open request$"):
            apply("request", {**body, "request_id": new})
        apply("request", {**body, "request_id": new, "supersedes": old}, controller.SUPERSEDE_EVENT_SCHEMA)
        if index % 2:
            apply("withdraw", {"request_id": new, "source": "fixture"})
        else:
            apply("grant", {"request_id": new})
            with pytest.raises(ValueError, match="^holder already has an open request$"):
                apply("request", {**body, "request_id": "refused"})
            apply("release", {"request_id": new, "evidence": {"path": str(CONTROLLER), "sha256": "a" * 64}})
        apply("set_limits", {"source": "fixture", "heavy_limit": 1})
    assert ledger.requests.visits <= ledger.seq
    assert controller.capacity_view(ledger)[kind]["used"] == 0


class Workspace:
    def __init__(self, tmp_path):
        self.tmp = tmp_path
        self.store = tmp_path / "store"

    def argv(self, command, request=None, **flags):
        argv = [sys.executable, "-I", str(CONTROLLER), "--store", str(self.store), command]
        if request is not None:
            path = self.tmp / ("request-%d-%d.json" % (os.getpid(), time.monotonic_ns()))
            path.write_text(json.dumps(request), encoding="utf-8")
            argv += ["--request", str(path)]
        for name, value in flags.items():
            argv += ["--" + name.replace("_", "-"), str(value)]
        return argv

    def run(self, command, request=None, *, expect=0, raw=False, **flags):
        argv = self.argv(command, request, **flags)
        result = subprocess.run(argv, capture_output=True, text=True, timeout=30,
                                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
        assert not result.stderr, result.stderr
        assert result.returncode == expect, result.stdout
        return result.stdout if raw else json.loads(result.stdout)

    def register(self, identifier, project="aegis", priority=10, **extra):
        return self.run("register", {"id": identifier, "project": project, "repository": project, "priority": priority,
                                     "target_branch": "develop", **extra})

    def ask(self, initiative, kind="writer", holder=None):
        return self.run("request", {"initiative": initiative, "kind": kind,
                                    "holder": holder or initiative + "/lane"})["request"]["request_id"]

    def grant(self, kind="writer"):
        return self.run("grant-next", kind=kind)["granted"]

    def evidence(self, name="terminal.json"):
        path = self.tmp / name
        path.write_text('{"exit": 0}\n')
        return {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}

    def release(self, request_id):
        return self.run("release", {"request_id": request_id, "evidence": self.evidence()})


@pytest.fixture
def workspace(tmp_path):
    space = Workspace(tmp_path)
    space.run("init", {"writer_limit": 3, "heavy_limit": 1})
    return space


def memo_store(space):
    if not controller._memo_supported():
        pytest.skip("workspace memo needs checked POSIX descriptor reads")
    return controller.Store(space.store)


def test_store_replays_only_new_events_and_rebuilds_changed_or_missing_keys(workspace, monkeypatch):
    workspace.register("a1")
    old = workspace.ask("a1")
    store = memo_store(workspace)
    applied = []
    original = controller.Ledger.apply

    def apply(ledger, event):
        applied.append(event["seq"])
        return original(ledger, event)

    monkeypatch.setattr(controller.Ledger, "apply", apply)
    first = store.load()
    assert applied == [1, 2, 3]
    applied.clear()
    assert store.load().requests == first.requests
    assert applied == []
    workspace.run("request", {"initiative": "a1", "kind": "writer", "holder": "a1/lane", "supersedes": old})
    assert store.load().requests[old]["state"] == "withdrawn"
    assert applied == [4]
    applied.clear()
    path = event_files(workspace)[1]
    event = json.loads(path.read_text())
    event["data"]["priority"] = 20
    metadata = path.stat()
    path.write_bytes(controller.encoded(event) + b"\n")
    assert path.stat().st_size == metadata.st_size
    os.utime(path, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
    assert store.load().initiatives["a1"]["priority"] == 20
    assert applied == [1, 2, 3, 4]
    applied.clear()
    event_files(workspace)[-1].unlink()
    assert store.load().requests[old]["state"] == "queued"
    assert applied == [1, 2, 3]


def test_store_memo_isolated_from_callers_and_failed_publication(workspace, monkeypatch):
    workspace.register("a1")
    store = memo_store(workspace)
    ledger = store.load()
    ledger.initiatives["a1"]["priority"] = 999
    assert store.load().initiatives["a1"]["priority"] == 10

    def refuse(*args):
        raise OSError("fixture publication failure")

    monkeypatch.setattr(controller, "publish_file", refuse)
    with pytest.raises(OSError, match="^fixture publication failure$"):
        store.append(ledger, "request", {"request_id": "req-00000003", "initiative": "a1",
                                         "kind": "writer", "holder": "same"})
    assert store.load().requests == {}


@pytest.mark.parametrize("report_first", [False, True])
def test_store_memo_keeps_report_timestamp_leniency_separate(workspace, report_first):
    workspace.register("a1")
    identifier = workspace.ask("a1")
    store = memo_store(workspace)
    store.load()
    path = event_files(workspace)[-1]
    event = json.loads(path.read_text())
    event["at"] = "invalid fixture timestamp"
    path.write_text(json.dumps(event))

    def strict():
        with pytest.raises(ValueError, match="malformed workspace event:"):
            store.load()

    if not report_first:
        strict()
    assert store.load(for_report=True).requests[identifier]["requested_at"] is None
    strict()


def test_store_without_descriptor_support_replays_without_a_memo(workspace, monkeypatch):
    monkeypatch.setattr(controller, "_memo_supported", lambda: False)
    store = controller.Store(workspace.store)
    assert store.load().seq == 1
    workspace.register("a1")
    assert store.load().seq == 2


@pytest.mark.parametrize("damage,error", [
    ("gap", "nonconsecutive workspace event:"),
    ("malformed", "malformed workspace event:"),
    ("unexpected", "unexpected workspace store entry:"),
    ("oversized", "input exceeds 262144 bytes"),
])
def test_warm_store_still_refuses_damaged_history(workspace, damage, error):
    workspace.register("a1")
    workspace.ask("a1")
    store = memo_store(workspace)
    store.load()
    paths = event_files(workspace)
    if damage == "gap":
        paths[1].unlink()
    elif damage == "malformed":
        paths[-1].write_bytes(b"{")
    elif damage == "unexpected":
        (workspace.store / "events" / "surprise").write_bytes(b"{}")
    else:
        paths[-1].write_bytes(b" " * (controller.MAX_BYTES + 1))
    with pytest.raises(ValueError, match=error):
        store.load()


def test_warm_store_replays_after_directory_replacement_with_unchanged_file_keys(workspace, monkeypatch):
    workspace.register("a1")
    store = memo_store(workspace)
    replacement = workspace.store / "replacement-events"
    replacement.mkdir()
    for path in store.events.iterdir():
        os.link(path, replacement / path.name)
    store.load()
    before = [(path.name, path.stat()) for path in sorted(store.events.iterdir())]
    store.events.rename(workspace.store / "old-events")
    replacement.rename(store.events)
    assert [(path.name, path.stat()) for path in sorted(store.events.iterdir())] == before
    applied = []
    original = controller.Ledger.apply

    def apply(ledger, event):
        applied.append(event["seq"])
        return original(ledger, event)

    monkeypatch.setattr(controller.Ledger, "apply", apply)
    assert store.load().seq == 2
    assert applied == [1, 2]


@pytest.mark.parametrize("pending", [False, True])
def test_warm_store_refuses_symlinks(workspace, pending):
    store = memo_store(workspace)
    store.load()
    target = workspace.tmp / "target.json"
    target.write_bytes(event_files(workspace)[0].read_bytes())
    link = store.events / (".pending-fixture" if pending else "00000001.json")
    if not pending:
        link.unlink()
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    with pytest.raises(ValueError, match="symlink paths are not supported:"):
        store.load()


@pytest.mark.parametrize("component", ["store", "events", "00000001.json"])
def test_store_never_follows_a_concurrent_symlink_swap_and_closes_descriptors(workspace, monkeypatch, component):
    store = memo_store(workspace)
    original_open, original_close = os.open, os.close
    opened = set()
    swapped = []
    victim = store.path if component == "store" else store.events if component == "events" else event_files(workspace)[0]
    replacement = workspace.tmp / "replacement"
    if victim.is_dir():
        replacement.mkdir()
    else:
        replacement.write_text("{}")
    # Probe before injecting the race, so platforms that prohibit links skip cleanly.
    probe = workspace.tmp / "symlink-probe"
    try:
        probe.symlink_to(replacement, target_is_directory=replacement.is_dir())
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    probe.unlink()

    def open_path(path, flags, *args, **kwargs):
        if str(path) == component and not swapped:
            victim.rename(victim.with_name(victim.name + "-old"))
            victim.symlink_to(replacement, target_is_directory=replacement.is_dir())
            swapped.append(True)
        descriptor = original_open(path, flags, *args, **kwargs)
        opened.add(descriptor)
        return descriptor

    def close(descriptor):
        opened.remove(descriptor)
        return original_close(descriptor)

    monkeypatch.setattr(controller, "os", SimpleNamespace(**{**vars(os), "open": open_path, "close": close}))
    with pytest.raises(ValueError, match="workspace event (directory )?is unavailable"):
        store.load()
    assert swapped and not opened


@pytest.mark.parametrize("request_body,error", [
    ({"writer_limit": 6, "heavy_limit": 1}, "invalid writer_limit"),
    ({"writer_limit": 3, "heavy_limit": 4}, "invalid heavy_limit"),
    ({"writer_limit": 3, "heavy_limit": 0}, "invalid heavy_limit"),
    ({"writer_limit": 0, "heavy_limit": 1}, "invalid writer_limit"),
    ({"writer_limit": 3}, "missing fields"),
    ({"writer_limit": 3, "heavy_limit": 1, "heavy_tests_limit": 2}, "invalid heavy_tests_limit"),
    ({"writer_limit": 3, "heavy_limit": 1, "heavy_tests_limit": 0}, "invalid heavy_tests_limit"),
])
def test_init_refuses_caps_beyond_the_owner_limits(tmp_path, request_body, error):
    space = Workspace(tmp_path)
    assert error in space.run("init", request_body, expect=2)["error"]
    assert not (space.store / "events").exists() or not list((space.store / "events").iterdir())


def test_init_accepts_the_owners_five_writers(tmp_path):
    space = Workspace(tmp_path)
    assert space.run("init", {"writer_limit": 5, "heavy_limit": 3})["limits"]["writer"] == 5
    assert space.run("status")["capacity"]["writer"]["limit"] == 5


def test_init_accepts_an_explicit_heavy_tests_limit_of_one(tmp_path):
    limits = Workspace(tmp_path).run("init", {"writer_limit": 5, "heavy_limit": 3, "heavy_tests_limit": 1})["limits"]
    assert limits == {"writer": 5, "heavy": 3, "heavy-tests": 1}


def test_heavy_tests_is_one_separate_slot_and_an_old_store_loads_with_it(tmp_path):
    space = Workspace(tmp_path)
    space.run("init", {"writer_limit": 3, "heavy_limit": 3})
    assert json.loads(event_files(space)[0].read_text())["data"] == {"writer_limit": 3, "heavy_limit": 3}
    assert space.run("status")["capacity"]["heavy-tests"] == {"limit": 1, "used": 0, "free": 1, "holders": []}
    space.register("a1")
    cargo = [space.ask("a1", "heavy-tests", "a1/cargo-%d" % index) for index in range(2)]
    space.ask("a1", "heavy", "a1/pytest")
    assert space.grant("heavy-tests")["request_id"] == cargo[0]
    assert space.run("grant-next", kind="heavy-tests", expect=3)["reason"] == "capacity_full"
    assert space.grant("heavy")["holder"] == "a1/pytest"
    capacity = space.run("status")["capacity"]
    assert capacity["heavy"]["used"] == 1 and capacity["heavy-tests"]["used"] == 1
    assert "Heavy-Tests 1/1" in space.run("report", raw=True, format="text")
    space.release(cargo[0])
    assert space.run("status")["capacity"]["heavy-tests"]["used"] == 0
    assert space.grant("heavy-tests")["request_id"] == cargo[1]


def test_three_heavy_jobs_can_run_at_the_owners_limit_and_a_fourth_waits(tmp_path):
    space = Workspace(tmp_path)
    assert space.run("init", {"writer_limit": 3, "heavy_limit": 3})["limits"]["heavy"] == 3
    space.register("a1")
    for index in range(4):
        space.ask("a1", "heavy", "a1/job-%d" % index)
    for _ in range(3):
        space.grant("heavy")
    assert space.run("grant-next", kind="heavy", expect=3)["reason"] == "capacity_full"
    assert space.run("status")["capacity"]["heavy"]["used"] == 3


def test_init_does_not_replace_an_existing_store(workspace):
    refused = workspace.run("init", {"writer_limit": 3, "heavy_limit": 1}, expect=2)
    assert refused["error"] == "workspace store already exists"


def test_commands_refuse_an_uninitialized_store(tmp_path):
    assert Workspace(tmp_path).run("status", expect=2)["error"] == "workspace store is not initialized"


def test_registered_initiatives_are_listed_and_duplicates_refused(workspace):
    checkout = str(workspace.tmp / "clone")
    workspace.register("aegis-47", priority=5, touched_paths=["tools/**"], checkouts=[checkout])
    record = workspace.run("status")["initiatives"]["aegis-47"]
    assert record["priority"] == 5 and record["state"] == "active"
    assert record["touched_paths"] == ["tools/**"] and record["base_moved"] is None
    assert record["checkouts"] == [checkout]
    refused = workspace.run("register", {"id": "aegis-47", "project": "aegis", "repository": "aegis", "priority": 5,
                                         "target_branch": "develop"}, expect=2)
    assert refused["error"] == "initiative already registered: aegis-47"


@pytest.mark.parametrize("change,error", [
    ({"id": "../escape"}, "invalid initiative id"),
    ({"project": "Not A Slug"}, "invalid project"),
    ({"priority": 0}, "invalid priority"),
    ({"priority": True}, "invalid priority"),
    ({"checkouts": ["relative/path"]}, "checkout must be absolute"),
    ({"mailbox_root": "relative"}, "mailbox_root must be absolute"),
    ({"touched_paths": "tools/**"}, "invalid touched paths"),
    ({"run": "rm -rf /"}, "unexpected fields"),
])
def test_malformed_initiatives_are_refused(workspace, change, error):
    body = {"id": "valid", "project": "aegis", "repository": "aegis", "priority": 5, "target_branch": "develop", **change}
    assert error in workspace.run("register", body, expect=2)["error"]
    assert workspace.run("status")["initiatives"] == {}


def test_updates_need_a_source_and_a_known_initiative(workspace):
    workspace.register("aegis-47")
    assert "missing fields" in workspace.run("update", {"initiative": "aegis-47", "priority": 1}, expect=2)["error"]
    refused = workspace.run("update", {"initiative": "unknown", "source": "owner", "priority": 1}, expect=2)
    assert refused["error"] == "initiative is not registered: unknown"
    assert "invalid initiative state" in workspace.run(
        "update", {"initiative": "aegis-47", "source": "owner", "state": "approved"}, expect=2)["error"]
    workspace.run("update", {"initiative": "aegis-47", "source": "owner via front door message", "priority": 1})
    assert workspace.run("status")["initiatives"]["aegis-47"]["priority"] == 1


def test_a_fourth_writer_across_two_projects_is_refused(workspace):
    for name, project in (("a1", "aegis"), ("a2", "aegis"), ("s1", "stormheir"), ("s2", "stormheir")):
        workspace.register(name, project=project)
        workspace.ask(name)
    assert [workspace.grant()["initiative"] for _ in range(3)] == ["a1", "a2", "s1"]
    refused = workspace.run("grant-next", kind="writer", expect=3)
    assert refused["granted"] is None and refused["reason"] == "capacity_full"
    assert sorted(row["initiative"] for row in refused["holders"]) == ["a1", "a2", "s1"]
    capacity = workspace.run("status")["capacity"]["writer"]
    assert capacity["used"] == 3 and capacity["free"] == 0
    assert [row["initiative"] for row in workspace.run("status")["capacity"]["queue"]] == ["s2"]


def test_a_second_heavy_job_is_refused_and_writers_are_counted_separately(workspace):
    workspace.register("a1")
    workspace.ask("a1", "heavy", "a1/full-suite")
    workspace.ask("a1", "heavy", "a1/hook")
    workspace.ask("a1", "writer", "a1/lane")
    assert workspace.grant("heavy")["holder"] == "a1/full-suite"
    assert workspace.run("grant-next", kind="heavy", expect=3)["reason"] == "capacity_full"
    assert workspace.grant("writer")["holder"] == "a1/lane"


def test_higher_priority_goes_first_then_the_oldest_request(workspace):
    workspace.register("late-low", priority=30)
    workspace.register("first-mid", priority=20)
    workspace.register("second-mid", priority=20)
    workspace.register("urgent", priority=1)
    for name in ("late-low", "first-mid", "second-mid", "urgent"):
        workspace.ask(name, "heavy")
    order = []
    for _ in range(4):
        granted = workspace.grant("heavy")
        order.append(granted["initiative"])
        workspace.release(granted["request_id"])
    assert order == ["urgent", "first-mid", "second-mid", "late-low"]


def test_accepted_work_is_never_preempted(workspace):
    workspace.register("low", priority=50)
    workspace.register("urgent", priority=1)
    held = [workspace.ask("low", holder="low/%d" % index) for index in range(3)]
    for _ in held:
        workspace.grant()
    workspace.ask("urgent")
    assert workspace.run("grant-next", kind="writer", expect=3)["reason"] == "capacity_full"
    assert workspace.run("status")["capacity"]["writer"]["used"] == 3
    workspace.release(held[0])
    assert workspace.grant()["initiative"] == "urgent"


def test_an_unlisted_initiative_is_refused_not_guessed(workspace):
    refused = workspace.run("request", {"initiative": "unlisted", "kind": "writer", "holder": "x"}, expect=2)
    assert refused["error"] == "initiative is not registered: unlisted"


def test_malformed_requests_are_refused(workspace):
    workspace.register("a1")
    assert "invalid kind" in workspace.run("request", {"initiative": "a1", "kind": "gpu", "holder": "x"}, expect=2)["error"]
    workspace.ask("a1", holder="same")
    refused = workspace.run("request", {"initiative": "a1", "kind": "writer", "holder": "same"}, expect=2)
    assert refused["error"] == "holder already has an open request"


def test_a_blocked_initiative_waits_until_its_blocker_is_done(workspace):
    workspace.register("first")
    workspace.register("second", priority=1, blocked_by=["first"])
    workspace.ask("second")
    refused = workspace.run("grant-next", kind="writer", expect=3)
    assert refused["reason"] == "all_blocked"
    assert refused["waiting"][0]["blocked_by"] == ["first"]
    workspace.run("update", {"initiative": "first", "source": "owner merged it", "state": "done"})
    assert workspace.grant()["initiative"] == "second"


def test_an_external_blocker_holds_until_it_is_removed(workspace):
    workspace.register("p1", blocked_by=["pr-259"])
    workspace.ask("p1")
    assert workspace.run("grant-next", kind="writer", expect=3)["reason"] == "all_blocked"
    workspace.run("update", {"initiative": "p1", "source": "owner", "blocked_by": []})
    assert workspace.grant()["initiative"] == "p1"


def test_a_paused_initiative_cannot_ask_and_its_queue_waits(workspace):
    workspace.register("a1")
    workspace.ask("a1")
    workspace.run("update", {"initiative": "a1", "source": "owner", "state": "paused"})
    assert workspace.run("grant-next", kind="writer", expect=3)["reason"] == "all_blocked"
    refused = workspace.run("request", {"initiative": "a1", "kind": "heavy", "holder": "x"}, expect=2)
    assert refused["error"] == "initiative is not active: a1"


def test_a_reservation_is_kept_until_terminal_evidence_exists(workspace):
    workspace.register("a1")
    workspace.ask("a1", "heavy")
    request_id = workspace.grant("heavy")["request_id"]
    assert "missing fields" in workspace.run("release", {"request_id": request_id}, expect=2)["error"]
    missing = {"path": str(workspace.tmp / "absent.json"), "sha256": "c" * 64}
    assert "terminal evidence is unavailable" in workspace.run(
        "release", {"request_id": request_id, "evidence": missing}, expect=2)["error"]
    wrong = {**workspace.evidence(), "sha256": "c" * 64}
    assert workspace.run("release", {"request_id": request_id, "evidence": wrong},
                         expect=2)["error"] == "terminal evidence does not match its hash"
    assert workspace.run("status")["capacity"]["heavy"]["used"] == 1
    workspace.release(request_id)
    assert workspace.run("status")["capacity"]["heavy"]["used"] == 0
    assert workspace.run("release", {"request_id": request_id, "evidence": workspace.evidence()},
                         expect=2)["error"] == "request is not granted: " + request_id


def test_only_queued_requests_can_be_withdrawn(workspace):
    workspace.register("a1")
    queued = workspace.ask("a1", holder="queued")
    held = workspace.grant()["request_id"]
    assert held == queued
    assert workspace.run("withdraw", {"request_id": held, "source": "orchestrator"},
                         expect=2)["error"] == "request is not queued: " + held
    second = workspace.ask("a1", holder="second")
    workspace.run("withdraw", {"request_id": second, "source": "orchestrator"})
    assert workspace.run("grant-next", kind="writer", expect=3)["reason"] == "queue_empty"


def test_an_initiative_cannot_finish_while_it_holds_capacity(workspace):
    workspace.register("a1")
    workspace.ask("a1")
    workspace.grant()
    refused = workspace.run("update", {"initiative": "a1", "source": "owner", "state": "done"}, expect=2)
    assert refused["error"] == "initiative still holds capacity or queued requests: a1"


def test_concurrent_grants_never_exceed_the_cap(workspace):
    workspace.register("a1")
    for index in range(8):
        workspace.ask("a1", holder="lane-%d" % index)
    argv = workspace.argv("grant-next", kind="writer")
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    processes = [subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
                 for _ in range(8)]
    results = [(process.communicate(timeout=30), process.returncode) for process in processes]
    for (_, stderr), _ in results:
        assert not stderr
    assert {code for _, code in results} <= {0, 2, 3}
    for (stdout, _), code in results:
        if code == 2:
            assert json.loads(stdout) == {"error": "workspace store is busy; inspect an abandoned lock before retrying"}
    assert workspace.run("status")["capacity"]["writer"]["used"] <= 3


def clone_pair(tmp_path):
    seed = tmp_path / "seed"
    seed.mkdir()
    git(seed, "init", "-q", "-b", "develop")
    (seed / ".aegis").mkdir()
    (seed / ".aegis/config.json").write_text('{"v":1}\n')
    (seed / ".gitignore").write_text(".aegis/state/\n")
    (seed / "README.md").write_text("fixture\n")
    git(seed, "add", ".aegis/config.json", ".gitignore", "README.md")
    git(seed, "commit", "-qm", "baseline")
    clones = []
    for name in ("clone-a", "clone-b"):
        target = tmp_path / name
        git(tmp_path, "clone", "-q", "--no-hardlinks", str(seed), str(target))
        clones.append(target)
    return clones


def write_lease(checkout, lane, paths, *, ts=None, ttl=3600, raw=None):
    blob = raw if raw is not None else json.dumps({
        "v": 1, "lane": lane, "role": "implementer", "owner": "test@host", "claim_id": "9f2c0d1e2b3a4f56", "gen": 1,
        "branch": "lane/" + lane, "paths": paths, "ts": int(time.time()) if ts is None else ts, "ttl_s": ttl})
    oid = subprocess.run(["git", "hash-object", "-w", "--stdin"], cwd=checkout, input=blob, text=True,
                         capture_output=True, check=True, timeout=10).stdout.strip()
    git(checkout, "update-ref", "refs/aegis/lanes/" + lane, oid)


@pytest.fixture
def two_clones(workspace, tmp_path):
    first, second = clone_pair(tmp_path)
    workspace.register("first", checkouts=[str(first)])
    workspace.register("second", checkouts=[str(second)])
    return first, second


@pytest.mark.parametrize("held,wanted,reason", [
    (None, "docs/a b.md", "usage"),
    (None, "docs/a\tb.md", "usage"),
    (None, "docs/a\nb.md", "usage"),
    (["docs/a.py / src/b.py"], "other/file.py", "overlap"),
    (["docs/a.py src/b.py"], "src/b.py", "overlap"),
    (["src/**"], "src/nested/file.py", "overlap"),
    (["src/*.py"], "src/file.txt", "overlap"),
    (["src/a?.py"], "src/ab.py", "overlap"),
    (["/docs/"], "docs/guide.md", "overlap"),
    (["/Docs/"], "docs/guide.md", "overlap"),
    (["src/**"], "docs/guide.md", "clear"),
    (["/docs/"], "nested/docs/guide.md", "clear"),
    (None, "/docs/", "clear"),
    (None, "docs\\guide.md", "clear"),
    (None, "docs/file:part.md", "clear"),
    (None, "docs/" + "a" * 4096, "clear"),
], ids=["space", "tab", "newline", "legacy-slash", "legacy-union", "double-star", "star", "question",
        "directory", "case", "disjoint", "anchored-disjoint", "request-anchor", "backslash", "colon", "long"])
def test_workspace_path_check_agrees_with_real_claim(workspace, tmp_path, held, wanted, reason):
    checkout, _ = clone_pair(tmp_path)
    workspace.register("a1", checkouts=[str(checkout)])
    if held is not None:
        write_lease(checkout, "foreign", held)
    before = {p.name: p.read_bytes() for p in event_files(workspace)}
    ledger = controller.Store(workspace.store).load()
    for _ in range(2):
        if reason == "usage":
            with pytest.raises(lease_reader.TeamUsageError) as claim_error:
                lease_reader.claim(checkout, "candidate", [wanted])
            with pytest.raises(ValueError) as check_error:
                controller.check_paths(ledger, "a1", [wanted])
            assert str(check_error.value) == str(claim_error.value)
            assert workspace.run("check-paths", {"initiative": "a1", "paths": [wanted]}, expect=2) == {
                "error": str(claim_error.value)}
        else:
            code, result = controller.check_paths(ledger, "a1", [wanted])
            assert code == (3 if reason == "overlap" else 0)
            assert result["conflict"] is (reason == "overlap")
            if reason == "overlap":
                with pytest.raises(lease_reader.LeaseRefused) as claim_error:
                    lease_reader.claim(checkout, "candidate", [wanted])
                assert claim_error.value.reason == "overlap"
                assert [row["lane"] for row in result["conflicts"]] == ["foreign"]
            else:
                change = lease_reader.claim(checkout, "candidate", [wanted])
                lease_reader.release(checkout, "candidate", change.oid)
    assert before == {p.name: p.read_bytes() for p in event_files(workspace)}


def test_workspace_path_check_and_claim_reread_a_concurrent_foreign_lease(workspace, tmp_path, monkeypatch):
    checkout, _ = clone_pair(tmp_path)
    workspace.register("a1", checkouts=[str(checkout)])
    write_lease(checkout, "foreign", ["/docs/"])
    read_leases = lease_reader.read_leases
    replaced = []

    def read_then_replace(root):
        found = read_leases(root)
        if not replaced:
            write_lease(checkout, "foreign", ["/src/"])
            replaced.append(True)
        return found

    monkeypatch.setattr(lease_reader, "read_leases", read_then_replace)
    ledger = controller.Store(workspace.store).load()
    assert controller.check_paths(ledger, "a1", ["src/file.py"])[0] == 0
    for _ in range(2):
        with pytest.raises(lease_reader.LeaseRefused) as error:
            lease_reader.claim(checkout, "candidate", ["src/file.py"])
        assert error.value.reason == "overlap"
        code, result = controller.check_paths(ledger, "a1", ["src/file.py"])
        assert code == 3 and result["conflicts"][0]["lane"] == "foreign"
    assert replaced == [True]


@pytest.mark.parametrize("reserved", [False, True], ids=["declared", "reserved"])
@pytest.mark.parametrize("held,wanted,overlap", [
    (["/docs/"], "nested/docs/file.md", False),
    (["/Docs/"], "docs/file.md", True),
    (["docs/a.md src/b.py"], "src/b.py", True),
    (["src/a?.py"], "src/abc.txt", True),
    (["src/**"], "docs/file.md", False),
    ([], "src/file.py", False),
], ids=["anchor-disjoint", "case", "legacy-union", "conservative-glob", "disjoint", "empty"])
def test_workspace_declared_and_reserved_overlap_agrees_with_real_claim(
        workspace, tmp_path, reserved, held, wanted, overlap):
    checkout, _ = clone_pair(tmp_path)
    workspace.register("owner", touched_paths=held)
    workspace.register("a1", checkouts=[str(checkout)])
    if held:
        write_lease(checkout, "foreign", held)
        if overlap:
            with pytest.raises(lease_reader.LeaseRefused) as error:
                lease_reader.claim(checkout, "candidate", [wanted])
            assert error.value.reason == "overlap"
        else:
            change = lease_reader.claim(checkout, "candidate", [wanted])
            lease_reader.release(checkout, "candidate", change.oid)
        lease_reader.release(checkout, "foreign", git(checkout, "rev-parse", "refs/aegis/lanes/foreign"))
    if reserved:
        workspace.ask("owner")
        workspace.grant()
    for _ in range(2):
        result = workspace.run("check-paths", {"initiative": "a1", "paths": [wanted]},
                               expect=3 if reserved and overlap else 0)
        assert result["declared_overlaps"] == (["owner"] if overlap else [])
        assert bool(result["reserved_conflicts"]) is (reserved and overlap)
        assert result["conflicts"] == []


@pytest.mark.parametrize("paths", [
    None, "docs/**", [], [None], [1], [""], ["/"], ["../escape"], ["docs/\x00name"],
    ["docs/\udcffname"], ["x" * (lease_reader.MAX_LEASE_BYTES + 1)],
    ["a" * (lease_reader.MAX_LEASE_BYTES // 2 + 1), "b" * (lease_reader.MAX_LEASE_BYTES // 2 + 1)],
    ["docs/good.md", "docs/../escape"],
], ids=["null", "not-list", "empty-list", "null-glob", "number-glob", "empty-glob", "empty-anchor",
        "traversal", "nul", "surrogate", "oversize", "aggregate-oversize", "late-invalid"])
def test_workspace_invalid_paths_use_claim_refusal_before_lease_io(workspace, paths, monkeypatch):
    workspace.register("a1", checkouts=[str(workspace.tmp)])

    def unexpected_read(*args):
        raise AssertionError("invalid paths reached the lease reader")

    monkeypatch.setattr(lease_reader, "read_leases", unexpected_read)
    expected = claim_path_refusal(workspace, paths)
    ledger = controller.Store(workspace.store).load()
    for _ in range(2):
        with pytest.raises(ValueError) as error:
            controller.check_paths(ledger, "a1", paths)
        assert str(error.value) == expected


@pytest.mark.parametrize("paths", [["docs/a.md"] * 257, ("docs/a.md",), ("docs/token=SYNTHETIC_GM3_SECRET",)],
                         ids=["many-globs", "tuple", "tuple-secret"])
def test_workspace_claim_valid_path_collections_are_not_locally_restricted(workspace, tmp_path, paths):
    checkout, _ = clone_pair(tmp_path)
    workspace.register("a1", checkouts=[str(checkout)])
    code, result = controller.check_paths(controller.Store(workspace.store).load(), "a1", paths)
    assert code == 0 and result["conflict"] is False
    change = lease_reader.claim(checkout, "candidate", paths)
    try:
        code, result = controller.check_paths(controller.Store(workspace.store).load(), "a1", paths)
        assert code == 3 and result["conflict"] is True
        assert result["paths"] == [fingerprint(path) if "SYNTHETIC" in path else path for path in paths]
        assert "SYNTHETIC" not in json.dumps(result)
        with pytest.raises(lease_reader.LeaseRefused) as error:
            lease_reader.claim(checkout, "contender", paths)
        assert error.value.reason == "overlap"
    finally:
        lease_reader.release(checkout, "candidate", change.oid)
    assert controller.check_paths(controller.Store(workspace.store).load(), "a1", paths)[0] == 0


@pytest.mark.parametrize("reserved", [False, True], ids=["declared", "reserved"])
@pytest.mark.parametrize("held", [["docs/a.md / src/b.py"], ["../escape"], [" "]],
                         ids=["legacy-slash", "traversal", "empty-legacy"])
def test_workspace_unreadable_stored_scopes_conservatively_overlap(workspace, tmp_path, reserved, held):
    checkout, _ = clone_pair(tmp_path)
    workspace.register("owner", touched_paths=held)
    workspace.register("a1", checkouts=[str(checkout)])
    write_lease(checkout, "foreign", held)
    with pytest.raises(lease_reader.LeaseRefused) as error:
        lease_reader.claim(checkout, "candidate", ["other/file.md"])
    assert error.value.reason == "overlap"
    lease_reader.release(checkout, "foreign", git(checkout, "rev-parse", "refs/aegis/lanes/foreign"))
    if reserved:
        workspace.ask("owner")
        workspace.grant()
    for _ in range(2):
        result = workspace.run("check-paths", {"initiative": "a1", "paths": ["other/file.md"]},
                               expect=3 if reserved else 0)
        assert result["declared_overlaps"] == ["owner"]
        assert bool(result["reserved_conflicts"]) is reserved


@pytest.fixture
def recovery_jobs(monkeypatch):
    from tools import hierarchy_jobs

    # Replace the external process census, keeping recovery and real store/lease
    # reads portable on hosts without /proc. No global OS reference is patched.
    def census(store_path, ledger, fixture, kind):
        return {"limit": ledger.limits[kind], "held": len(ledger.held(kind)),
                "external_roots": [], "census": "fixture"}

    monkeypatch.setattr("tools.hierarchy_jobs.census", census)
    return hierarchy_jobs


@pytest.mark.parametrize("stored,expected", [
    (["docs/a.md src/b.py"], 0),
    (["docs/a.md / src/b.py"], 3),
    (["../token=SYNTHETIC_GM5_SECRET"], 3),
    (["docs/a.md"], 0),
    (["/docs/"], 0),
    ([], 0),
], ids=["legacy", "unparseable", "unparseable-secret", "valid", "anchor", "empty"])
def test_recovery_inventory_reads_stored_scope_and_keeps_new_requests_strict(
        workspace, recovery_jobs, capsys, stored, expected):
    workspace.register("a1", touched_paths=stored)
    before = {path.name: path.read_bytes() for path in event_files(workspace)}
    new_paths = ["docs/a.md src/b.py"]
    refusal = {"error": claim_path_refusal(workspace, new_paths)}
    for _ in range(2):
        code = recovery_jobs.main(["--store", str(workspace.store), "recovery-status"])
        raw = capsys.readouterr().out
        report = json.loads(raw)
        assert code == expected, report
        assert set(report) == {"schema", "read_only", "seq", "capacity", "capacity_scope", "process_census",
                               "initiatives", "jobs", "blockers", "native_qualification"}
        assert report["schema"] == "aegis.hierarchy-recovery-status/v1" and report["read_only"] is True
        assert report["jobs"] == [] and report["native_qualification"] == "not_established"
        assert [row["id"] for row in report["initiatives"]] == ["a1"]
        assert [row["reason"] for row in report["blockers"]] == (["path_conflict"] if expected == 3 else [])
        team = report["initiatives"][0]
        if stored:
            paths = team["paths"]
            assert paths["conflict"] is (expected == 3)
            assert set(paths) >= {"initiative", "paths", "conflict", "conflicts", "reserved_conflicts",
                                  "unreadable_checkouts", "own_overlaps", "declared_overlaps", "checked_checkouts"}
            if expected == 3:
                assert paths["reason"] == "stored_paths_unreadable"
                # The path-conflict subreport owns the refusal display boundary;
                # recovery also inventories the separately registered metadata.
                assert "SYNTHETIC" not in json.dumps(paths)
                if "SYNTHETIC" in stored[0]:
                    assert paths["paths"] == [fingerprint(stored[0])]
            else:
                assert paths["paths"] == stored
        else:
            assert "paths" not in team
        assert workspace.run("check-paths", {"initiative": "a1", "paths": new_paths}, expect=2) == refusal
        assert {path.name: path.read_bytes() for path in event_files(workspace)} == before


def test_recovery_stored_scope_rechecks_a_concurrent_foreign_lease(
        workspace, tmp_path, recovery_jobs, monkeypatch, capsys):
    checkout, _ = clone_pair(tmp_path)
    workspace.register("a1", checkouts=[str(checkout)], touched_paths=["docs/a.md src/b.py"])
    write_lease(checkout, "foreign", ["other/**"])
    read_leases = lease_reader.read_leases
    replaced = []

    def read_then_replace(root):
        found = read_leases(root)
        if not replaced:
            write_lease(checkout, "foreign", ["src/b.py"])
            replaced.append(True)
        return found

    monkeypatch.setattr(lease_reader, "read_leases", read_then_replace)
    before = {path.name: path.read_bytes() for path in event_files(workspace)}
    for expected in (0, 3, 3):
        code = recovery_jobs.main(["--store", str(workspace.store), "recovery-status"])
        report = json.loads(capsys.readouterr().out)
        assert code == expected, report
        paths = report["initiatives"][0]["paths"]
        assert paths["conflict"] is (expected == 3)
        assert [row["lane"] for row in paths["conflicts"]] == (["foreign"] if expected == 3 else [])
        assert [row["reason"] for row in report["blockers"]] == (["path_conflict"] if expected == 3 else [])
    assert replaced == [True]
    assert {path.name: path.read_bytes() for path in event_files(workspace)} == before


def test_registered_empty_scope_is_clear_while_empty_new_request_is_refused(workspace, monkeypatch):
    workspace.register("a1", checkouts=[str(workspace.tmp / "unavailable")])
    workspace.register("peer", touched_paths=["../escape"])
    workspace.ask("peer")
    workspace.grant()

    def unexpected_read(*args):
        raise AssertionError("an empty stored scope reached the lease reader")

    monkeypatch.setattr(lease_reader, "read_leases", unexpected_read)
    ledger = controller.Store(workspace.store).load()
    code, report = controller.check_initiative_paths(ledger, "a1")
    assert code == 0 and report["paths"] == [] and report["conflict"] is False
    assert report["checked_checkouts"] == 0 and report["declared_overlaps"] == []
    assert report["reserved_conflicts"] == [] and report["unreadable_checkouts"] == []
    with pytest.raises(ValueError) as error:
        controller.check_paths(ledger, "a1", [])
    assert str(error.value) == claim_path_refusal(workspace, [])


@pytest.mark.parametrize("checkout_component", ["clones", "clones with space"])
def test_a_real_lease_in_another_clone_conflicts_though_that_clone_cannot_see_it(workspace, checkout_component):
    checkout_root = workspace.tmp / checkout_component
    checkout_root.mkdir()
    first, second = clone_pair(checkout_root)
    workspace.register("first", checkouts=[str(first)])
    workspace.register("second", checkouts=[str(second)])
    aegis(first, "team", "claim", "first-lane", "--paths", "src/a/**")
    assert aegis(second, "team", "list").get("leases", []) == []
    conflict = workspace.run("check-paths", {"initiative": "second", "paths": ["src/a/value.txt"]}, expect=3)
    assert conflict["conflict"] is True
    row = conflict["conflicts"][0]
    checkout = str(first)
    displayed_checkout = controller._display(checkout)
    if " " in checkout:
        assert displayed_checkout == fingerprint(checkout)
    assert row["lane"] == "first-lane" and row["initiative"] == "first" and row["checkout"] == displayed_checkout
    clear = workspace.run("check-paths", {"initiative": "second", "paths": ["src/b/**"]})
    assert clear["conflict"] is False and clear["conflicts"] == []


@pytest.mark.parametrize("held,wanted,expired,conflict", [
    (["src/a/**"], "src/a/value.txt", False, True),
    (["src/a/**"], "src/b/value.txt", False, False),
    (["/pyproject.toml"], "pyproject.toml", False, True),
    (["/pyproject.toml"], "nested/pyproject.toml", False, False),
    (["/docs/"], "docs/guide.md", False, True),
    (["/docs/"], "nested/docs/guide.md", False, False),
    (["README.md"], "nested/README.md", False, True),
    (["docs/a.py src/b.py"], "src/b.py", False, True),
    ([".//pyproject.toml"], "nested/pyproject.toml", False, True),
    (["src/**"], "src/value.txt", True, False),
    ([" "], "other/value.txt", True, True),
])
def test_workspace_lease_parser_preserves_scope_exit_codes_and_read_only_checks(
        workspace, two_clones, held, wanted, expired, conflict):
    first, _ = two_clones
    write_lease(first, "peer-lane", held, ts=100 if expired else None, ttl=1 if expired else 3600)
    before = {p.name: p.read_bytes() for p in event_files(workspace)}
    oid = git(first, "rev-parse", "refs/aegis/lanes/peer-lane")
    for _ in range(2):
        result = workspace.run("check-paths", {"initiative": "second", "paths": [wanted]},
                               expect=3 if conflict else 0)
        assert result["conflict"] is conflict
        assert [row["lane"] for row in result["conflicts"]] == (["peer-lane"] if conflict else [])
        assert result["checked_checkouts"] == 2
    assert before == {p.name: p.read_bytes() for p in event_files(workspace)}
    assert git(first, "rev-parse", "refs/aegis/lanes/peer-lane") == oid


@pytest.mark.parametrize("held,hit,miss", [
    (["/pyproject.toml"], "pyproject.toml", "nested/pyproject.toml"),
    (["docs/a.py src/b.py"], "src/b.py", "other/value.txt"),
])
def test_workspace_lease_parser_keeps_mailbox_mcp_alive_across_overlap_frames(tmp_path, held, hit, miss):
    from tests.integration.test_hierarchy_role_tools import Team

    built = Team(tmp_path)
    first, second = clone_pair(tmp_path)
    built.workspace.register("own", checkouts=[str(first)])
    built.workspace.register("peer", checkouts=[str(second)])
    write_lease(second, "peer-lane", held)
    before = {p.name: p.read_bytes() for p in event_files(built.workspace)}
    responses = built.responses("a/lane/f2", [
        ("workspace_path_overlap", {"paths": [path]}) for path in (hit, miss, hit)])
    tools = [row["result"] for row in responses[2:]]
    assert len(tools) == 3 and all(not row.get("isError", False) for row in tools)
    assert [json.loads(row["content"][0]["text"])["conflict"] for row in tools] == [True, False, True]
    assert before == {p.name: p.read_bytes() for p in event_files(built.workspace)}


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="the job runner reads /proc")
def test_workspace_lease_parser_allows_jobs_with_a_disjoint_live_lease(tmp_path, tmp_path_factory, request):
    from tests.integration.test_hierarchy_jobs import Shop, commit_request
    from tests.integration.test_hierarchy_provision import worker_source_seed

    shop = Shop(tmp_path, source_seed=worker_source_seed(tmp_path_factory, request))
    write_lease(shop.checkout, "root-file-lane", ["/pyproject.toml"])
    commit_request(shop)
    assert shop.run_open()["rows"][0]["state"] == "completed"
    assert shop.states("job-1") == ["started", "completed"]
    shop.workspace.run("update", {"initiative": "pilot", "source": "fixture", "touched_paths": ["src/app.py"]})
    report = shop.jobs("recovery-status", expect=0)
    assert report["initiatives"][0]["paths"]["conflict"] is False


def test_workspace_lease_parser_rechecks_a_replaced_lease_on_the_next_observation(workspace, two_clones, monkeypatch):
    first, _ = two_clones
    write_lease(first, "peer-lane", ["/pyproject.toml"])
    original = lease_reader.read_leases
    replaced = []

    def read_then_replace(checkout):
        observed = original(checkout)
        if checkout == first and not replaced:
            write_lease(first, "peer-lane", ["nested/pyproject.toml"])
            replaced.append(True)
        return observed

    monkeypatch.setattr(lease_reader, "read_leases", read_then_replace)
    ledger = controller.Store(workspace.store).load()
    # The check is advisory: the first observation retains its parsed snapshot,
    # and the next public call must read the new scope rather than cache it.
    for expected in (0, 3, 3):
        code, result = controller.check_paths(ledger, "second", ["nested/pyproject.toml"])
        assert code == expected and result["conflict"] is (expected == 3)
    assert replaced == [True]


@pytest.mark.parametrize("raw", ["a.py /", "a.py ..", " ", "docs/a.py src/b.py"],
                         ids=["empty-component", "parent", "empty-split", "whitespace-request"])
def test_workspace_lease_parser_refuses_invalid_request_components_before_reading_leases(
        workspace, two_clones, raw, monkeypatch):
    def unexpected_read(*args):
        raise AssertionError("invalid request reached the lease reader")

    monkeypatch.setattr(lease_reader, "read_leases", unexpected_read)
    expected = claim_path_refusal(workspace, [raw])
    with pytest.raises(ValueError) as error:
        controller.check_paths(controller.Store(workspace.store).load(), "second", [raw])
    assert str(error.value) == expected
    response = workspace.run("check-paths", {"initiative": "second", "paths": [raw]}, expect=2)
    assert response == {"error": expected}


def test_an_expired_lease_does_not_conflict(workspace, two_clones):
    first, _ = two_clones
    write_lease(first, "old-lane", ["src/**"], ts=int(time.time()) - 7200, ttl=60)
    assert workspace.run("check-paths", {"initiative": "second", "paths": ["src/x.txt"]})["conflict"] is False


def test_an_unreadable_lease_counts_as_a_conflict(workspace, two_clones):
    first, _ = two_clones
    write_lease(first, "broken-lane", None, raw="not a lease")
    conflict = workspace.run("check-paths", {"initiative": "second", "paths": ["anything.txt"]}, expect=3)
    assert conflict["conflicts"][0]["lane"] == "broken-lane"
    assert "unreadable" in conflict["conflicts"][0]


def test_an_unavailable_checkout_counts_as_a_conflict(workspace, tmp_path):
    workspace.register("gone", checkouts=[str(tmp_path / "missing-clone")])
    workspace.register("second")
    conflict = workspace.run("check-paths", {"initiative": "second", "paths": ["anything.txt"]}, expect=3)
    assert conflict["unreadable_checkouts"][0]["initiative"] == "gone"


def test_an_initiatives_own_lease_is_reported_but_is_not_a_conflict(workspace, two_clones):
    first, _ = two_clones
    workspace.run("update", {"initiative": "first", "source": "root", "lanes": ["first-lane"]})
    write_lease(first, "first-lane", ["src/**"])
    result = workspace.run("check-paths", {"initiative": "first", "paths": ["src/x.txt"]})
    assert result["conflict"] is False
    assert result["own_overlaps"][0]["lane"] == "first-lane"
    assert result["own_overlaps"][0]["assigned_to"] == "first"


def shared_git_initiatives(workspace, tmp_path):
    first, _ = clone_pair(tmp_path)
    linked = tmp_path / "linked-worktree"
    git(first, "worktree", "add", "-q", str(linked), "-b", "lane/other")
    workspace.register("own", checkouts=[str(first)], lanes=["own-lane"])
    workspace.register("peer", checkouts=[str(linked)], lanes=["peer-lane"])
    write_lease(first, "own-lane", ["src/**"])
    return first, linked


def test_a_shared_git_directory_does_not_turn_an_own_lease_into_a_conflict(workspace, tmp_path):
    shared_git_initiatives(workspace, tmp_path)
    result = workspace.run("check-paths", {"initiative": "own", "paths": ["src/x.txt"]})
    assert result["conflict"] is False
    assert [row["lane"] for row in result["own_overlaps"]] == ["own-lane"]


def test_the_other_initiative_sees_that_same_lease_as_a_conflict_with_its_owner(workspace, tmp_path):
    shared_git_initiatives(workspace, tmp_path)
    conflict = workspace.run("check-paths", {"initiative": "peer", "paths": ["src/x.txt"]}, expect=3)
    assert conflict["own_overlaps"] == []
    row = conflict["conflicts"][0]
    assert row["lane"] == "own-lane" and row["assigned_to"] == "own"


def test_an_unassigned_lease_in_your_own_checkout_is_a_conflict(workspace, two_clones):
    first, _ = two_clones
    write_lease(first, "nobodys-lane", ["src/**"])
    conflict = workspace.run("check-paths", {"initiative": "first", "paths": ["src/x.txt"]}, expect=3)
    assert conflict["conflicts"][0]["assigned_to"] is None
    assert conflict["own_overlaps"] == []


def test_your_lane_name_in_a_clone_you_do_not_use_is_a_conflict(workspace, two_clones):
    _, second = two_clones
    workspace.run("update", {"initiative": "first", "source": "root", "lanes": ["reused-name"]})
    write_lease(second, "reused-name", ["src/**"])
    conflict = workspace.run("check-paths", {"initiative": "first", "paths": ["src/x.txt"]}, expect=3)
    assert conflict["conflicts"][0]["lane"] == "reused-name"
    assert conflict["own_overlaps"] == []


def test_a_lane_has_one_owner_per_repository(workspace):
    workspace.register("first", lanes=["shared-name"])
    refused = workspace.run("register", {"id": "second", "project": "aegis", "repository": "aegis", "priority": 5,
                                         "target_branch": "develop", "lanes": ["shared-name"]}, expect=2)
    assert refused["error"] == "lane already belongs to initiative first: shared-name"
    workspace.register("second")
    refused = workspace.run("update", {"initiative": "second", "source": "root", "lanes": ["shared-name"]}, expect=2)
    assert refused["error"] == "lane already belongs to initiative first: shared-name"
    workspace.register("elsewhere", project="stormheir", lanes=["shared-name"])
    workspace.run("update", {"initiative": "first", "source": "root", "lanes": ["shared-name", "extra"]})
    assert workspace.run("status")["initiatives"]["first"]["lanes"] == ["shared-name", "extra"]


def test_malformed_lane_lists_are_refused(workspace):
    workspace.register("first")
    refused = workspace.run("update", {"initiative": "first", "source": "root", "lanes": "one-lane"}, expect=2)
    assert "invalid lanes" in refused["error"]


def test_visibility_through_a_shared_git_directory_is_not_ownership(workspace, tmp_path):
    first, _ = clone_pair(tmp_path)
    linked = tmp_path / "linked-worktree"
    git(first, "worktree", "add", "-q", str(linked), "-b", "lane/other")
    workspace.register("holder", checkouts=[str(first)])
    workspace.register("peer", checkouts=[str(linked)])
    write_lease(first, "holder-lane", ["src/**"])
    conflict = workspace.run("check-paths", {"initiative": "peer", "paths": ["src/x.txt"]}, expect=3)
    assert conflict["conflict"] is True
    assert [row["lane"] for row in conflict["conflicts"]] == ["holder-lane"]
    assert conflict["own_overlaps"] == []


def test_another_repository_never_conflicts(workspace, tmp_path):
    first, second = clone_pair(tmp_path)
    workspace.register("elsewhere", project="stormheir", checkouts=[str(first)])
    workspace.register("here", checkouts=[str(second)])
    write_lease(first, "other-repo-lane", ["src/**"])
    assert workspace.run("check-paths", {"initiative": "here", "paths": ["src/x.txt"]})["conflict"] is False


def test_declared_paths_warn_without_refusing(workspace):
    workspace.register("first", touched_paths=["tools/**"])
    workspace.register("second")
    result = workspace.run("check-paths", {"initiative": "second", "paths": ["tools/x.py"]})
    assert result["conflict"] is False and result["declared_overlaps"] == ["first"]


@pytest.mark.parametrize("paths", [["/../escape"], ["../escape"], [], "tools/**"])
def test_malformed_path_checks_are_refused(workspace, paths):
    workspace.register("first")
    expected = claim_path_refusal(workspace, paths)
    assert workspace.run("check-paths", {"initiative": "first", "paths": paths}, expect=2) == {"error": expected}


def test_a_missing_lease_reader_is_a_clear_error(workspace, tmp_path):
    workspace.register("first")
    copy = tmp_path / "copied-tools"
    copy.mkdir()
    for name in ("hierarchy_mailbox.py", "hierarchy_workspace_display.py", "hierarchy_workspace.py"):
        (copy / name).write_bytes((CONTROLLER.parent / name).read_bytes())
    request = tmp_path / "paths.json"
    request.write_text(json.dumps({"initiative": "first", "paths": ["x.txt"]}), encoding="utf-8")
    result = subprocess.run([sys.executable, "-I", str(copy / "hierarchy_workspace.py"), "--store", str(workspace.store),
                             "check-paths", "--request", str(request)], capture_output=True, text=True, timeout=20,
                            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert result.returncode == 2 and not result.stderr
    assert json.loads(result.stdout) == {"error": "the Aegis lease reader is unavailable from this checkout"}


@pytest.mark.parametrize("checkout_reader,preloaded", [
    (False, None), (True, None), (True, "package"), (True, "search_path"),
])
def test_path_checks_use_only_the_reader_from_the_tools_checkout(workspace, tmp_path, checkout_reader, preloaded):
    workspace.register("first")
    environment = tmp_path / "python"
    venv.EnvBuilder(with_pip=False).create(environment)
    python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    probe = subprocess.run([str(python), "-I", "-c", "import sysconfig; print(sysconfig.get_path('purelib'))"],
                           capture_output=True, text=True, timeout=20, check=True)
    installed = Path(probe.stdout.strip()) / "aegis_core"
    shutil.copytree(ROOT / "aegis_core", installed, ignore=shutil.ignore_patterns("__pycache__"))
    marker = tmp_path / "foreign-reader-imported"
    initializer = installed / "__init__.py"
    initializer.write_text("from pathlib import Path\nPath(%r).write_text('imported')\n" % str(marker)
                           + initializer.read_text(encoding="utf-8"), encoding="utf-8")
    reader = installed / "match.py"
    reader.write_text(reader.read_text(encoding="utf-8")
                      + "\nfrom pathlib import Path\nPath(%r).write_text('reader imported')\n" % str(marker),
                      encoding="utf-8")
    source = tmp_path / "source"
    copied_tools = source / "tools"
    copied_tools.mkdir(parents=True)
    for name in ("hierarchy_mailbox.py", "hierarchy_workspace_display.py", "hierarchy_workspace.py"):
        shutil.copyfile(CONTROLLER.parent / name, copied_tools / name)
    if checkout_reader:
        shutil.copytree(ROOT / "aegis_core", source / "aegis_core", ignore=shutil.ignore_patterns("__pycache__"))
    request = tmp_path / "paths.json"
    request.write_text(json.dumps({"initiative": "first", "paths": ["x.txt"]}), encoding="utf-8")
    argv = [str(python), "-I"]
    if preloaded == "package":
        argv += ["-c", "import aegis_core,runpy,sys; sys.argv=sys.argv[1:]; runpy.run_path(sys.argv[0], run_name='__main__')"]
    elif preloaded == "search_path":
        argv += ["-c", ("import runpy,sys; sys.path.insert(0,%r); import aegis_core; "
                        "aegis_core.__path__=[%r]; sys.argv=sys.argv[1:]; "
                        "runpy.run_path(sys.argv[0], run_name='__main__')") % (str(source), str(installed))]
    argv += [str(copied_tools / "hierarchy_workspace.py"), "--store", str(workspace.store),
             "check-paths", "--request", str(request)]
    before = {p.name: p.read_bytes() for p in (workspace.store / "events").iterdir()}
    result = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    assert not result.stderr, result.stderr
    if checkout_reader and not preloaded:
        assert result.returncode == 0, result.stdout
        assert json.loads(result.stdout)["conflict"] is False
    else:
        assert result.returncode == 2, result.stdout
        assert json.loads(result.stdout) == {"error": "the Aegis lease reader is unavailable from this checkout"}
    assert marker.exists() is (preloaded == "package")
    assert before == {p.name: p.read_bytes() for p in (workspace.store / "events").iterdir()}


def test_an_initial_priority_can_name_its_source(workspace):
    workspace.register("a1", source="owner chat 2026-11-02")
    assert workspace.run("status")["initiatives"]["a1"]["source"] == "owner chat 2026-11-02"
    refused = workspace.run("register", {"id": "a2", "project": "aegis", "repository": "aegis", "priority": 5,
                                         "target_branch": "develop", "source": ""}, expect=2)
    assert refused["error"] == "invalid source"


def test_a_merge_marks_only_other_initiatives_on_that_branch(workspace):
    workspace.register("merged")
    workspace.register("same-branch")
    workspace.run("register", {"id": "other-branch", "project": "aegis", "repository": "aegis", "priority": 5,
                               "target_branch": "release"})
    workspace.register("other-repo", project="stormheir")
    result = workspace.run("mark-merge", {"repository": "aegis", "branch": "develop", "commit": COMMIT,
                                          "initiative": "merged", "source": "owner merged PR 1"})
    assert result["marked"] == ["same-branch"]
    blocked = workspace.run("check-delivery", initiative="same-branch", expect=3)
    assert blocked["ready"] is False and blocked["base_moved"]["commit"] == COMMIT
    for name in ("merged", "other-branch", "other-repo"):
        assert workspace.run("check-delivery", initiative=name)["ready"] is True


def test_revalidation_needs_evidence_and_the_latest_moved_base(workspace):
    workspace.register("merged")
    workspace.register("waiting")
    workspace.run("mark-merge", {"repository": "aegis", "branch": "develop", "commit": COMMIT,
                                 "initiative": "merged", "source": "owner"})
    workspace.run("mark-merge", {"repository": "aegis", "branch": "develop", "commit": LATER_COMMIT,
                                 "initiative": "merged", "source": "owner"})
    stale = workspace.run("clear-base-moved", {"initiative": "waiting", "base_commit": COMMIT, "source": "lane check",
                                               "evidence": workspace.evidence()}, expect=2)
    assert stale["error"] == "revalidation does not match the latest moved base"
    assert "missing fields" in workspace.run("clear-base-moved", {"initiative": "waiting", "base_commit": LATER_COMMIT,
                                                                  "source": "lane check"}, expect=2)["error"]
    workspace.run("clear-base-moved", {"initiative": "waiting", "base_commit": LATER_COMMIT, "source": "lane check",
                                       "evidence": workspace.evidence()})
    assert workspace.run("check-delivery", initiative="waiting")["ready"] is True
    refused = workspace.run("clear-base-moved", {"initiative": "waiting", "base_commit": LATER_COMMIT,
                                                 "source": "lane check", "evidence": workspace.evidence()}, expect=2)
    assert refused["error"] == "initiative has no moved base: waiting"


def test_blocked_or_paused_initiatives_are_not_ready_for_delivery(workspace):
    workspace.register("blocker")
    workspace.register("blocked", blocked_by=["blocker"])
    workspace.register("paused")
    workspace.run("update", {"initiative": "paused", "source": "owner", "state": "paused"})
    assert workspace.run("check-delivery", initiative="blocked", expect=3)["blocked_by"] == ["blocker"]
    assert workspace.run("check-delivery", initiative="paused", expect=3)["state"] == "paused"
    assert workspace.run("check-delivery", initiative="unknown", expect=2)["error"] == "initiative is not registered: unknown"


def event_files(workspace):
    return sorted((workspace.store / "events").glob("*.json"))


@pytest.mark.parametrize("damage,error", [
    (lambda path: path.write_text("{truncated"), "malformed workspace event"),
    (lambda path: path.unlink(), "nonconsecutive workspace event"),
    (lambda path: path.write_text(json.dumps({**json.loads(path.read_text()), "kind": "approve"})), "unknown workspace event"),
    (lambda path: path.write_text(json.dumps({**json.loads(path.read_text()), "extra": 1})), "unexpected fields"),
])
def test_a_damaged_store_fails_loudly_for_reads_and_writes(workspace, damage, error):
    workspace.register("a1")
    workspace.register("a2")
    damage(event_files(workspace)[1])
    for command, request, flags in (("status", None, {}), ("grant-next", None, {"kind": "writer"}),
                                    ("request", {"initiative": "a2", "kind": "writer", "holder": "x"}, {})):
        assert error in workspace.run(command, request, expect=2, **flags)["error"]


@pytest.mark.parametrize("name", ["00000002.json", ".pending-00000002.json"])
def test_a_symlinked_store_entry_fails_loudly(workspace, tmp_path, name):
    workspace.register("a1")
    target = event_files(workspace)[1]
    copy = tmp_path / "elsewhere.json"
    copy.write_bytes(target.read_bytes())
    if not name.startswith(".pending-"):
        target.unlink()
    (workspace.store / "events" / name).symlink_to(copy)
    assert "symlink paths are not supported" in workspace.run("status", expect=2)["error"]


def test_a_hand_edited_grant_beyond_the_cap_is_detected(workspace):
    workspace.register("a1")
    for index in range(4):
        workspace.ask("a1", holder="lane-%d" % index)
    for _ in range(3):
        workspace.grant()
    last = event_files(workspace)[-1]
    sequence = len(event_files(workspace)) + 1
    document = json.loads(last.read_text())
    requests = workspace.run("status")["capacity"]["queue"]
    document.update(seq=sequence, data={"request_id": requests[0]["request_id"]})
    (workspace.store / "events" / ("%08d.json" % sequence)).write_text(json.dumps(document))
    assert "ledger grant exceeds capacity" in workspace.run("status", expect=2)["error"]


def fill_store_to_the_limit(workspace, initiative):
    template = json.loads(event_files(workspace)[-1].read_text())
    for sequence in range(len(event_files(workspace)) + 1, 10001):
        event = {**template, "seq": sequence, "kind": "update", "data": {"initiative": initiative, "source": "fixture"}}
        (workspace.store / "events" / ("%08d.json" % sequence)).write_text(json.dumps(event))


def test_a_full_store_refuses_more_events_and_stays_readable(workspace):
    workspace.register("a1")
    workspace.ask("a1", "heavy")
    held = workspace.grant("heavy")["request_id"]
    fill_store_to_the_limit(workspace, "a1")
    assert workspace.run("status")["seq"] == 10000
    refused = workspace.run("update", {"initiative": "a1", "source": "owner", "priority": 1}, expect=2)
    assert refused["error"] == "workspace event history limit reached"
    assert not (workspace.store / "events" / "00010001.json").exists()
    status = workspace.run("status")
    assert status["seq"] == 10000 and status["capacity"]["heavy"]["used"] == 1
    assert status["initiatives"]["a1"]["priority"] == 10
    for command, request, flags in (("request", {"initiative": "a1", "kind": "writer", "holder": "x"}, {}),
                                    ("release", {"request_id": held, "evidence": workspace.evidence()}, {})):
        assert workspace.run(command, request, expect=2, **flags)["error"] == "workspace event history limit reached"
    assert workspace.run("report")["capacity"]["heavy"]["used"] == 1
    assert (workspace.store / ".write.lock").exists() is False


def test_the_last_free_event_is_still_accepted(workspace):
    workspace.register("a1")
    fill_store_to_the_limit(workspace, "a1")
    (workspace.store / "events" / "00010000.json").unlink()
    workspace.run("update", {"initiative": "a1", "source": "owner", "priority": 1})
    status = workspace.run("status")
    assert status["seq"] == 10000 and status["initiatives"]["a1"]["priority"] == 1


LIMITS_SOURCE = "owner-writers-5 requests/root-c6-owner-decisions-20261102.json"


def test_set_limits_raises_writers_to_five_and_a_reload_keeps_them(tmp_path):
    space = Workspace(tmp_path)
    space.run("init", {"writer_limit": 3, "heavy_limit": 3})
    space.register("a1")
    for index in range(6):
        space.ask("a1", holder="a1/lane-%d" % index)
    answer = space.run("set-limits", {"source": LIMITS_SOURCE, "writer_limit": 5})
    assert answer["limits"] == {"writer": 5, "heavy": 3, "heavy-tests": 1}
    assert answer["capacity"]["writer"]["limit"] == 5 and answer["capacity"]["writer"]["free"] == 5
    held = [space.grant()["request_id"] for _ in range(5)]
    assert space.run("grant-next", kind="writer", expect=3)["reason"] == "capacity_full"
    refused = space.run("set-limits", {"source": "owner", "writer_limit": 4}, expect=2)
    assert refused["error"] == "writer_limit 4 is below the 5 granted writer requests"
    space.release(held[0])
    space.run("set-limits", {"source": "owner", "writer_limit": 4, "heavy_limit": 2})
    capacity = space.run("status")["capacity"]
    assert (capacity["writer"]["limit"], capacity["writer"]["used"], capacity["heavy"]["limit"]) == (4, 4, 2)
    assert json.loads(event_files(space)[-1].read_text())["kind"] == "set_limits"


@pytest.mark.parametrize("body,error", [
    ({"source": LIMITS_SOURCE, "writer_limit": 1}, "writer_limit 1 is below the 2 granted writer requests"),
    ({"source": LIMITS_SOURCE, "writer_limit": 6}, "invalid writer_limit"),
    ({"source": LIMITS_SOURCE, "writer_limit": 0}, "invalid writer_limit"),
    ({"source": LIMITS_SOURCE, "heavy_limit": 4}, "invalid heavy_limit"),
    ({"source": LIMITS_SOURCE, "heavy_tests_limit": 2}, "invalid heavy_tests_limit"),
    ({"source": LIMITS_SOURCE, "writer_limit": 4, "gpu_limit": 1}, "unexpected fields: gpu_limit"),
    ({"writer_limit": 4}, "missing fields: source"),
    ({"source": "", "writer_limit": 4}, "invalid source"),
    ({"source": LIMITS_SOURCE}, "set-limits needs at least one limit"),
])
def test_set_limits_refuses_a_bad_change_and_writes_nothing(workspace, body, error):
    workspace.register("a1")
    for index in range(2):
        workspace.ask("a1", holder="a1/lane-%d" % index)
        workspace.grant()
    before = event_files(workspace)
    assert workspace.run("set-limits", body, expect=2)["error"] == error
    assert event_files(workspace) == before
    assert workspace.run("status")["capacity"]["writer"]["limit"] == 3


def test_a_full_store_refuses_set_limits_and_stays_readable(workspace):
    workspace.register("a1")
    fill_store_to_the_limit(workspace, "a1")
    refused = workspace.run("set-limits", {"source": LIMITS_SOURCE, "writer_limit": 5}, expect=2)
    assert refused["error"] == "workspace event history limit reached"
    status = workspace.run("status")
    assert status["seq"] == 10000 and status["capacity"]["writer"]["limit"] == 3


def test_a_busy_store_refuses_writes_but_still_answers_reads(workspace):
    workspace.register("a1")
    (workspace.store / ".write.lock").write_text("fixture active writer")
    refused = workspace.run("request", {"initiative": "a1", "kind": "writer", "holder": "x"}, expect=2)
    assert "workspace store is busy" in refused["error"]
    assert "a1" in workspace.run("status")["initiatives"]


def mailbox_with_mail(parent):
    parent.mkdir()
    root = parent / "mailbox"
    endpoints = {"a/front-door": {}, "a/orchestrator": {}, "a/root": {}}
    invoke(root, "init", {"schema": "aegis.hierarchy-pilot/v1", "endpoints": endpoints, "counterparts": [],
                          "writer_limit": 3})
    for endpoint in endpoints:
        invoke(root, "bind", {"endpoint": endpoint, "host": "host-one", "session": endpoint, "expected_generation": 0})
    invoke(root, "publish", message("a/front-door", "a/orchestrator", identifier="note"))
    packet = parent / "packet.md"
    packet.write_bytes(b"Run it.\n")
    invoke(root, "publish", message("a/orchestrator", "a/root", identifier="job", kind="job_request",
                                    brief={"path": str(packet), "sha256": hashlib.sha256(b"Run it.\n").hexdigest()}))
    return root


def test_the_report_gives_one_ordered_view_including_mailbox_facts(workspace, tmp_path):
    root = mailbox_with_mail(tmp_path / "alpha")
    workspace.register("low", priority=50, mailbox_root=str(root), delivery_dir=str(tmp_path / "alpha" / "delivery"))
    workspace.register("urgent", priority=1, blocked_by=["pr-259"], project="stormheir")
    workspace.register("gone", priority=20, mailbox_root=str(tmp_path / "absent" / "mailbox"))
    workspace.ask("low")
    workspace.grant()
    workspace.ask("low", "heavy")
    workspace.run("mark-merge", {"repository": "aegis", "branch": "develop", "commit": COMMIT, "source": "owner"})
    report = workspace.run("report")
    assert [row["id"] for row in report["initiatives"]] == ["urgent", "gone", "low"]
    low, urgent, gone = report["initiatives"][2], report["initiatives"][0], report["initiatives"][1]
    assert urgent["blocked_by"] == ["pr-259"]
    assert low["holds"] == {"writer": 1, "heavy": 0, "heavy-tests": 0}
    assert low["queued"] == {"writer": 0, "heavy": 1, "heavy-tests": 0}
    assert low["base_moved"]["commit"] == COMMIT
    assert low["mailbox"] == {"open_job_requests": 1, "accepted_writers": 0, "unread": 2, "messages": 2}
    assert "error" in gone["mailbox"]
    assert report["capacity"]["writer"]["used"] == 1
    assert report["generated_by"] == "script"
    text = workspace.run("report", raw=True, format="text")
    assert text.index("urgent") < text.index("low")
    assert "pr-259" in text and "1/3" in text and "base moved" in text


def test_the_report_counts_mailbox_writers_the_ledger_does_not_know(workspace, tmp_path):
    root = mailbox_with_mail(tmp_path / "alpha")
    workspace.register("a1", mailbox_root=str(root))
    assert workspace.run("report")["initiatives"][0]["mailbox"]["accepted_writers"] == 0


def test_status_is_read_only(workspace):
    workspace.register("a1")
    before = {path: path.read_bytes() for path in workspace.store.rglob("*") if path.is_file()}
    workspace.run("status")
    workspace.run("report")
    workspace.run("check-delivery", initiative="a1")
    workspace.run("check-paths", {"initiative": "a1", "paths": ["x.txt"]})
    assert {path: path.read_bytes() for path in workspace.store.rglob("*") if path.is_file()} == before


def test_five_initiatives_across_two_projects_keep_the_caps_and_the_priority_order(workspace, capsys, monkeypatch):
    def run(command, request=None, *, expect=0, raw=False, **flags):
        code = controller.main(workspace.argv(command, request, **flags)[3:])
        captured = capsys.readouterr()
        assert not captured.err, captured.err
        assert code == expect, captured.out
        return captured.out if raw else json.loads(captured.out)

    monkeypatch.setattr(workspace, "run", run)
    plan = {"a-45": ("aegis", 1), "a-47": ("aegis", 2), "a-docs": ("aegis", 40), "s-settings": ("stormheir", 3),
            "s-audio": ("stormheir", 30)}
    for name, (project, priority) in plan.items():
        workspace.register(name, project=project, priority=priority)
    rng = random.Random(47)
    open_requests, granted, sequence = [], [], 0
    for step in range(90):
        action = rng.choice(["request", "request", "grant", "grant", "release"])
        if action == "request":
            name = rng.choice(sorted(plan))
            kind = rng.choice(["writer", "writer", "heavy"])
            sequence += 1
            request_id = workspace.ask(name, kind, holder="%s/%d" % (name, sequence))
            open_requests.append({"request_id": request_id, "kind": kind, "priority": plan[name][1], "order": sequence})
        elif action == "grant":
            kind = rng.choice(["writer", "heavy"])
            limit = 3 if kind == "writer" else 1
            waiting = sorted((r for r in open_requests if r["kind"] == kind), key=lambda r: (r["priority"], r["order"]))
            held = sum(1 for r in granted if r["kind"] == kind)
            if held >= limit or not waiting:
                assert workspace.run("grant-next", kind=kind, expect=3)["granted"] is None
            else:
                assert workspace.grant(kind)["request_id"] == waiting[0]["request_id"]
                open_requests.remove(waiting[0])
                granted.append(waiting[0])
        elif granted:
            finished = granted.pop(rng.randrange(len(granted)))
            workspace.release(finished["request_id"])
        capacity = workspace.run("status")["capacity"]
        assert capacity["writer"]["used"] <= 3 and capacity["heavy"]["used"] <= 1
        assert capacity["writer"]["used"] == sum(1 for r in granted if r["kind"] == "writer")
        assert capacity["heavy"]["used"] == sum(1 for r in granted if r["kind"] == "heavy")
    assert Path(workspace.store).is_dir()


def test_store_can_replay_through_a_search_only_ancestor(workspace):
    store = memo_store(workspace)
    if os.geteuid() == 0:
        pytest.skip("root bypasses directory read permissions")
    mode = workspace.tmp.stat().st_mode & 0o7777
    try:
        workspace.tmp.chmod(0o111)
        assert store.load().seq == 1
        assert store.load().seq == 1
    finally:
        workspace.tmp.chmod(mode)


@pytest.mark.parametrize("damage", [None, "growth", "shrink", "growth-past-limit"],
                         ids=["unchanged", "growth", "shrink", "growth-past-limit"])
def test_store_load_completes_short_reads_and_retries_eintr(workspace, monkeypatch, damage):
    workspace.register("a1")
    workspace.ask("a1")
    workspace.grant()
    store = memo_store(workspace)
    expected = controller.Store(workspace.store).load()
    event = event_files(workspace)[0]
    original_bytes = event.read_bytes()
    delivered, descriptors, interrupted, changed = {}, set(), [], []
    chunks = []

    def read(descriptor, size):
        descriptors.add(descriptor)
        identity = os.fstat(descriptor).st_ino
        used = delivered.get(identity, 0)
        assert 0 < size <= controller.MAX_BYTES + 1 - used
        if chunks and not interrupted:
            interrupted.append(True)
            raise InterruptedError(errno.EINTR, "fixture interrupted read")
        chunk = os.read(descriptor, min(size, 17 if len(chunks) < 4 else 4096))
        chunks.append(chunk)
        delivered[identity] = used + len(chunk)
        if damage is not None and not changed:
            changed.append(True)
            if damage == "shrink":
                event.write_bytes(original_bytes[:-5])
            else:
                growth = 5 if damage == "growth" else controller.MAX_BYTES + 1
                event.write_bytes(original_bytes + b" " * growth)
        return chunk

    monkeypatch.setattr(controller, "os", SimpleNamespace(**{**vars(os), "read": read}))
    if damage is None:
        assert vars(store.load()) == vars(expected)
    else:
        with pytest.raises(ValueError, match="^malformed workspace event: .*: workspace event changed while reading$"):
            store.load()
        assert changed == [True]
    assert interrupted == [True]
    assert len(chunks) > 1
    assert all(size <= controller.MAX_BYTES + 1 for size in delivered.values())
    for descriptor in descriptors:
        with pytest.raises(OSError) as error:
            os.fstat(descriptor)
        assert error.value.errno == errno.EBADF


@pytest.mark.parametrize("value", [
    "/token=SYNTHETIC-S1", '/{"token":"SYNTHETIC-S2"}', "/password=SYNTHETIC-S3",
    "/ｔｏｋｅｎ=SYNTHETIC-S1", "/to\x1b[31mken=SYNTHETIC-S1", "/to\u200bken=SYNTHETIC-S1",
    "/token=" + "SYNTHETIC-S1" * 900, "/token=SYNTHETIC-S1\n\r\t\udcff",
    "/to\nken=SYNTHETIC-S1", "/pass\rword=SYNTHETIC-S3",
    "/to\x1b\u200b[31mken=SYNTHETIC-S1", "/prefix\nBearer SYNTHETIC_OPAQUE_1234567890",
    "/prefix\tghp_SYNTHETIC123456789012", "/auth=Bearer SYNTHETIC-S1",
    "/Authorization: Bearer SYNTHETIC-S1", "/prefixBearer SYNTHETIC_OPAQUE_1234567890",
    "/prefixghp_SYNTHETIC123456789012",
], ids=["token", "json", "password", "nfkc", "ansi", "format", "long", "non-utf8", "newline", "return",
        "ansi-format", "bearer-boundary", "token-boundary", "short-bearer-assignment", "header-bearer",
        "adjacent-bearer", "adjacent-token"])
def test_workspace_refusal_path_is_displayed(workspace, value):
    value = "../" + value
    workspace.register("a1")
    ledger = controller.Store(workspace.store).load()
    with pytest.raises(ValueError) as error:
        controller.check_paths(ledger, "a1", [value])
    message = str(error.value)
    assert message == claim_path_refusal(workspace, [value])
    assert "SYNTHETIC" not in message
    assert len(message) <= 600 and message.isprintable()
    raw = workspace.run("check-paths", {"initiative": "a1", "paths": [value]}, expect=2, raw=True)
    assert "SYNTHETIC" not in raw and raw.count("\n") == 1 and len(raw) <= 900


@pytest.mark.parametrize("command", ["init", "register", "update", "request", "withdraw", "release",
                                     "check-paths", "mark-merge", "clear-base-moved", "set-limits"])
@pytest.mark.parametrize("field", ["token=SYNTHETIC-S1", '{"token":"SYNTHETIC-S2"}',
                                   "password=SYNTHETIC-S3\n\x1b[31m"])
def test_workspace_request_refusals_do_not_echo_fields(workspace, tmp_path, command, field):
    space = Workspace(tmp_path / "fresh") if command == "init" else workspace
    if command == "init":
        space.tmp.mkdir()
    bodies = {
        "init": {"writer_limit": 3, "heavy_limit": 1},
        "register": {"id": "a1", "project": "aegis", "repository": "aegis", "priority": 1,
                     "target_branch": "develop"},
        "update": {"initiative": "a1", "source": "fixture"},
        "request": {"initiative": "a1", "kind": "writer", "holder": "fixture"},
        "withdraw": {"request_id": "req-00000001", "source": "fixture"},
        "release": {"request_id": "req-00000001", "evidence": space.evidence()},
        "check-paths": {"initiative": "a1", "paths": ["a.py"]},
        "mark-merge": {"repository": "aegis", "branch": "develop", "commit": COMMIT, "source": "fixture"},
        "clear-base-moved": {"initiative": "a1", "base_commit": COMMIT, "evidence": space.evidence(),
                             "source": "fixture"},
        "set-limits": {"source": "fixture", "writer_limit": 3},
    }
    raw = space.run(command, {**bodies[command], field: "unused"}, expect=2, raw=True)
    assert "SYNTHETIC" not in raw and raw.count("\n") == 1 and len(raw) <= 900
    assert not (space.store / ".write.lock").exists()


@pytest.mark.parametrize("failure", [ValueError, OSError, TypeError, UnicodeError, RecursionError, RuntimeError, KeyError])
def test_workspace_unexpected_main_exception_is_fixed(workspace, monkeypatch, capsys, failure):
    def refuse(args):
        raise failure("token=SYNTHETIC-S1\npassword=SYNTHETIC-S3")

    monkeypatch.setattr(controller, "run", refuse)
    assert controller.main(["--store", str(workspace.store), "status"]) == 2
    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out == json.dumps(FIXED_REFUSAL, sort_keys=True) + "\n"


@pytest.mark.parametrize("method", ["initiative", "request", "apply"])
def test_workspace_ledger_refusals_display_untrusted_values(method):
    ledger = controller.Ledger()
    value = '{"token":"SYNTHETIC-S2"}\n'
    argument = {"kind": value} if method == "apply" else value
    with pytest.raises(ValueError) as error:
        if method == "initiative":
            ledger.initiative(argument)
        elif method == "request":
            ledger.request(argument)
        else:
            ledger.apply(argument)
    assert "SYNTHETIC" not in str(error.value) and str(error.value).isprintable()


@pytest.mark.parametrize("name", ["token=SYNTHETIC-S1", 'password=SYNTHETIC-S3'], ids=["token", "password"])
def test_workspace_store_entry_refusals_display_names(workspace, name):
    (workspace.store / "events" / name).write_bytes(b"{}")
    with pytest.raises(ValueError) as error:
        controller.Store(workspace.store).load()
    assert "SYNTHETIC" not in str(error.value)
    raw = workspace.run("status", expect=2, raw=True)
    assert "SYNTHETIC" not in raw and raw.count("\n") == 1


def test_workspace_evidence_refusal_displays_untrusted_path(tmp_path):
    with pytest.raises(ValueError) as error:
        controller.verify_evidence({"path": str(tmp_path / "token=SYNTHETIC-S1"), "sha256": "a" * 64})
    assert "SYNTHETIC" not in str(error.value)


@pytest.mark.parametrize("site", ["checkout", "unreadable", "mailbox"])
def test_workspace_returned_errors_display_before_truncation(workspace, monkeypatch, site):
    marker = 'ｔｏｋｅｎ="' + "SYNTHETIC-S1" * 100 + '"\n\x1b[31m'

    def refuse(*args):
        raise ValueError(marker)

    if site == "mailbox":
        monkeypatch.setattr(controller, "Mailbox", refuse)
        result = controller.mailbox_facts({"mailbox_root": str(workspace.store)})
    else:
        workspace.register("a1", checkouts=[str(workspace.tmp)])
        match, team, paths = controller.lease_tools()
        reader = SimpleNamespace(read_leases=refuse)
        if site == "unreadable":
            reader.read_leases = lambda path: SimpleNamespace(
                leases=[], unreadable=[SimpleNamespace(lane="lane", oid="a" * 40, error=marker)])
        reader.glob_problem = team.glob_problem
        monkeypatch.setattr(controller, "lease_tools", lambda: (match, reader, paths))
        code, result = controller.check_paths(controller.Store(workspace.store).load(), "a1", ["a.py"])
        assert code == 3
    raw = json.dumps(result)
    assert "SYNTHETIC" not in raw and len(raw) < 1800
    def check_lines(value):
        if isinstance(value, dict):
            for item in value.values():
                check_lines(item)
        elif isinstance(value, list):
            for item in value:
                check_lines(item)
        elif isinstance(value, str):
            assert "\n" not in value and "\r" not in value
    check_lines(json.loads(raw))


@pytest.mark.parametrize("failure", ["fdopen", "write", "encode", "body"])
def test_workspace_lock_failure_closes_descriptor_and_allows_retry(workspace, monkeypatch, failure):
    store = controller.Store(workspace.store)
    opened, closed = [], []

    def open_fd(*args, **kwargs):
        descriptor = os.open(*args, **kwargs)
        opened.append(descriptor)
        return descriptor

    def close_fd(descriptor):
        closed.append(descriptor)
        return os.close(descriptor)

    def refuse(*args, **kwargs):
        raise OSError(errno.EIO, "fixture lock failure")

    class FailingStream:
        def __init__(self, closefd):
            self.closefd = closefd

        def __enter__(self):
            return self

        def write(self, raw):
            refuse()

        def __exit__(self, *args):
            if self.closefd:
                os.close(opened[-1])
                closed.append(opened[-1])

    def fdopen(descriptor, mode, **kwargs):
        if failure == "fdopen":
            refuse()
        if failure == "write":
            return FailingStream(kwargs.get("closefd", True))
        return os.fdopen(descriptor, mode, **kwargs)

    original_encoded = controller.encoded
    monkeypatch.setattr(controller, "os", SimpleNamespace(**{**vars(os), "open": open_fd, "close": close_fd,
                                                           "fdopen": fdopen}))
    if failure == "encode":
        monkeypatch.setattr(controller, "encoded", refuse)
    try:
        with pytest.raises(OSError, match="fixture lock failure"):
            with store.lock():
                assert failure == "body"
                refuse()
        for descriptor in opened:
            with pytest.raises(OSError) as error:
                os.fstat(descriptor)
            assert error.value.errno == errno.EBADF
        assert not (store.path / ".write.lock").exists()
    finally:
        # The RED fdopen reproducer must not leak into the test worker itself.
        for descriptor in opened:
            if descriptor not in closed:
                try:
                    os.close(descriptor)
                except OSError as error:
                    assert error.errno == errno.EBADF
        monkeypatch.setattr(controller, "os", os)
        monkeypatch.setattr(controller, "encoded", original_encoded)
    with store.lock():
        assert (store.path / ".write.lock").exists()
    assert not (store.path / ".write.lock").exists()


@pytest.mark.parametrize("site", ["anchor", "child", "leaf", "event"])
def test_workspace_descriptor_read_failure_closes_every_open(workspace, monkeypatch, site):
    store = memo_store(workspace)
    opened, closed = [], []

    def open_fd(*args, **kwargs):
        descriptor = os.open(*args, **kwargs)
        opened.append(descriptor)
        return descriptor

    def close_fd(descriptor):
        closed.append(descriptor)
        return os.close(descriptor)

    def fstat(descriptor):
        fail_at = {"anchor": 1, "child": 2, "leaf": len(store.events.parts)}
        if site != "event" and len(opened) == fail_at[site]:
            raise OSError(errno.EIO, "fixture fstat failure")
        if site == "event" and len(opened) == len(store.events.parts) + 1:
            raise OSError(errno.EIO, "fixture event fstat failure")
        return os.fstat(descriptor)

    monkeypatch.setattr(controller, "os", SimpleNamespace(**{**vars(os), "open": open_fd, "close": close_fd,
                                                           "fstat": fstat}))
    with pytest.raises(ValueError, match="workspace event (directory is unavailable|is unavailable)"):
        store.load()
    assert len(opened) == len(closed)
    for descriptor in opened:
        with pytest.raises(OSError) as error:
            os.fstat(descriptor)
        assert error.value.errno == errno.EBADF
    assert not (store.path / ".write.lock").exists()


def test_workspace_lock_busy_release_retry_uses_latches(workspace, monkeypatch, capsys):
    store = controller.Store(workspace.store)
    busy, released, acquired = threading.Event(), threading.Event(), threading.Event()
    errors, opened = [], []

    def open_fd(*args, **kwargs):
        descriptor = os.open(*args, **kwargs)
        opened.append(descriptor)
        return descriptor

    monkeypatch.setattr(controller, "os", SimpleNamespace(**{**vars(os), "open": open_fd}))

    def contender():
        try:
            with pytest.raises(ValueError, match="^workspace store is busy; inspect an abandoned lock before retrying$"):
                with store.lock():
                    pytest.fail("busy lock was acquired")
            busy.set()
            assert released.wait(10), "holder did not release"
            with store.lock():
                acquired.set()
        except BaseException as error:
            errors.append(error)
            busy.set()

    worker = threading.Thread(target=contender)
    try:
        with store.lock():
            worker.start()
            assert busy.wait(10), "contender did not observe busy"
            assert not acquired.is_set()
    finally:
        released.set()
        if worker.ident is not None:
            worker.join(10)
    assert not worker.is_alive() and not errors and acquired.is_set()
    assert not (store.path / ".write.lock").exists()
    assert len(opened) == 2
    for descriptor in opened:
        with pytest.raises(OSError) as error:
            os.fstat(descriptor)
        assert error.value.errno == errno.EBADF
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""


def test_workspace_fdopen_failure_keeps_cli_refusal_and_closes_fd(workspace, monkeypatch, capsys):
    opened = []

    def open_fd(*args, **kwargs):
        descriptor = os.open(*args, **kwargs)
        opened.append(descriptor)
        return descriptor

    def refuse(*args, **kwargs):
        raise OSError(errno.EIO, "token=SYNTHETIC-S1")

    monkeypatch.setattr(controller, "os", SimpleNamespace(**{**vars(os), "open": open_fd, "fdopen": refuse}))
    assert controller.main(workspace.argv("update", {"initiative": "a1", "source": "fixture"})[3:]) == 2
    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out == json.dumps({"error": fingerprint(str(OSError(errno.EIO, "token=SYNTHETIC-S1")))}) + "\n"
    assert not (workspace.store / ".write.lock").exists()
    assert len(opened) == 1
    for descriptor in opened:
        with pytest.raises(OSError) as error:
            os.fstat(descriptor)
        assert error.value.errno == errno.EBADF


def test_workspace_directory_parent_close_failure_also_closes_child(workspace, monkeypatch):
    store = memo_store(workspace)
    opened, live = [], set()
    failed = []

    def open_fd(*args, **kwargs):
        descriptor = os.open(*args, **kwargs)
        opened.append(descriptor)
        live.add(descriptor)
        return descriptor

    def close_fd(descriptor):
        if len(opened) == 2 and not failed:
            failed.append(True)
            os.close(descriptor)
            live.remove(descriptor)
            raise OSError(errno.EIO, "fixture parent close failure")
        os.close(descriptor)
        live.remove(descriptor)

    monkeypatch.setattr(controller, "os", SimpleNamespace(**{**vars(os), "open": open_fd, "close": close_fd}))
    try:
        with pytest.raises(ValueError, match="^workspace event directory is unavailable$"):
            store.load()
        assert not live
    finally:
        for descriptor in live:
            os.close(descriptor)


def test_workspace_conflict_response_displays_every_untrusted_field(workspace, monkeypatch):
    workspace.register("a1")
    match, team, paths = controller.lease_tools()
    lease = SimpleNamespace(lane="token=SYNTHETIC-S1", oid="a" * 40, paths=["password=SYNTHETIC-S3"],
                            path_set=paths.stored_paths(["a.py"]), owner='{"token":"SYNTHETIC-S2"}',
                            expired=lambda now: False, expires_at=123)
    reader = SimpleNamespace(glob_problem=team.glob_problem,
                             read_leases=lambda path: SimpleNamespace(leases=[lease], unreadable=[]))
    monkeypatch.setattr(controller, "lease_tools", lambda: (match, reader, paths))
    ledger = controller.Store(workspace.store).load()
    ledger.initiatives["a1"]["checkouts"] = [str(workspace.tmp / "token=SYNTHETIC-S1")]
    code, result = controller.check_paths(ledger, "a1", ["a.py"])
    assert code == 3
    assert "SYNTHETIC" not in json.dumps(result)


@pytest.mark.parametrize("command", ["init", "register", "update", "request", "withdraw", "release",
                                     "check-paths", "mark-merge", "clear-base-moved", "set-limits"])
def test_workspace_missing_request_path_is_displayed(workspace, command):
    argv = [sys.executable, "-I", str(CONTROLLER), "--store", str(workspace.store), command,
            "--request", str(workspace.tmp / "token=SYNTHETIC-S1")]
    result = subprocess.run(argv, capture_output=True, timeout=30)
    assert result.returncode == 2 and result.stderr == b""
    assert b"SYNTHETIC" not in result.stdout and result.stdout.count(b"\n") == 1
    refusal = json.loads(result.stdout)
    assert set(refusal) == {"error"} and refusal["error"].startswith("file unavailable: ")
    assert len(result.stdout) <= 900 and not (workspace.store / ".write.lock").exists()


@pytest.mark.parametrize("arguments", [
    ["token=SYNTHETIC-S1"], ["status", "--token=SYNTHETIC-S1"],
    ["report", "--format", 'password=SYNTHETIC-S3\n'],
], ids=["command", "option", "choice"])
def test_workspace_parser_refuses_without_echoing_arguments(workspace, arguments):
    result = subprocess.run([sys.executable, "-I", str(CONTROLLER), "--store", str(workspace.store)] + arguments,
                            capture_output=True, timeout=30)
    assert result.returncode == 2 and result.stderr == b""
    assert result.stdout == (b'{"error": "WORKSPACE_REFUSED", '
                             b'"next_action": "inspect the workspace inputs and retry"}' + os.linesep.encode("ascii"))


_CREDENTIAL_CORPUS = [
    ("bearer-assignment", "authorization=Bearer SYNTHETIC_OPAQUE_1234567890", "SYNTHETIC_OPAQUE_1234567890"),
    ("basic-assignment", "authorization=Basic SYNTHETIC_OPAQUE_1234567890", "SYNTHETIC_OPAQUE_1234567890"),
    ("digest-assignment", "authorization=Digest SYNTHETIC_OPAQUE_1234567890", "SYNTHETIC_OPAQUE_1234567890"),
    ("token-assignment", "authorization=Token SYNTHETIC_OPAQUE_1234567890", "SYNTHETIC_OPAQUE_1234567890"),
    ("negotiate-assignment", "authorization=Negotiate SYNTHETIC_OPAQUE_1234567890", "SYNTHETIC_OPAQUE_1234567890"),
    ("url", "https://fixture:SYNTHETIC_PASSWORD@example.test/path", "SYNTHETIC_PASSWORD"),
    ("jwt", "eyJSYNTHETIC1234.SYNTHETIC5678.SYNTHETIC9012", "eyJSYNTHETIC1234.SYNTHETIC5678.SYNTHETIC9012"),
    ("pem", "key=-----BEGIN PRIVATE KEY-----SYNTHETIC_PEM_BODY-----END PRIVATE KEY-----", "SYNTHETIC_PEM_BODY"),
    ("prose", "the password is SYNTHETIC_PASSWORD", "SYNTHETIC_PASSWORD"),
    ("json", '{"token":"SYNTHETIC_PASSWORD"}', "SYNTHETIC_PASSWORD"),
]
_CREDENTIAL_CORPUS += [(prefix, prefix + "A" * size, prefix + "A" * size) for prefix, size in (
    ("AKIA", 16), ("ASIA", 16), ("AGPA", 16), ("AIDA", 16), ("AROA", 16), ("ANPA", 16),
    ("ANVA", 16), ("AIPA", 16), ("ghp_", 20), ("gho_", 20), ("ghu_", 20), ("ghs_", 20),
    ("ghr_", 20), ("github_pat_", 20), ("glpat-", 16), ("sk_live_", 16), ("rk_test_", 16),
    ("pk_live_", 16), ("sk-", 20), ("sk-proj-", 20), ("sk-ant-", 20), ("AIza", 25),
    ("xoxa-", 10), ("xoxb-", 10), ("xoxp-", 10), ("xoxr-", 10), ("xoxs-", 10),
    ("npm_", 20), ("pypi-", 20))]


@pytest.mark.parametrize("label,value,credential", _CREDENTIAL_CORPUS, ids=[row[0] for row in _CREDENTIAL_CORPUS])
def test_workspace_credential_grammar_parity_and_public_refusal(workspace, label, value, credential):
    assert [(pattern.pattern, pattern.flags, replacement) for pattern, replacement, _ in controller._SECRET_REDACTIONS] == [
        (pattern.pattern, pattern.flags, replacement) for pattern, replacement in SECRET_REPLACEMENTS]
    reference = redact_command_secrets(value)
    assert reference != value
    with pytest.raises(ValueError) as error:
        controller.Ledger().initiative(value)
    assert str(error.value) == "initiative is not registered: " + fingerprint(value)
    workspace.register("a1")
    invalid = "../" + value
    expected = claim_path_refusal(workspace, [invalid])
    with pytest.raises(ValueError) as error:
        controller.check_paths(controller.Store(workspace.store).load(), "a1", [invalid])
    assert str(error.value) == expected
    result = subprocess.run(workspace.argv("check-paths", {"initiative": "a1", "paths": [invalid]}),
                            capture_output=True, timeout=30)
    assert result.returncode == 2 and result.stderr == b""
    refusal = json.loads(result.stdout)
    assert refusal == {"error": expected}
    assert credential not in refusal["error"]


@pytest.mark.parametrize("scheme", ["Basic", "Digest", "Token", "Negotiate"])
def test_workspace_bare_auth_scheme_credential_is_hidden(scheme):
    with pytest.raises(ValueError) as error:
        controller.Ledger().initiative(scheme + " SYNTHETIC_OPAQUE_1234567890")
    assert "SYNTHETIC_OPAQUE" not in str(error.value)


@pytest.mark.parametrize("identifier", ["sk-runner", "asia-launch", "ghp-docs", "akia-sync"])
def test_workspace_validated_ids_survive_delivery_requests_and_capacity(workspace, identifier):
    assert redact_command_secrets(identifier) == identifier
    workspace.register(identifier, blocked_by=["asia-launch"])
    code, result = controller.check_delivery(controller.Store(workspace.store).load(), identifier)
    assert code == 3 and result["initiative"] == identifier and result["blocked_by"] == ["asia-launch"]
    workspace.run("update", {"initiative": identifier, "source": "fixture", "state": "paused"})
    ledger = controller.Store(workspace.store).load()
    with pytest.raises(ValueError) as error:
        controller.apply_request(ledger, {"initiative": identifier, "request_id": "req-00000004",
                                         "kind": "writer", "holder": identifier}, {})
    assert str(error.value) == "initiative is not active: " + identifier
    workspace.run("update", {"initiative": identifier, "source": "fixture", "state": "active", "blocked_by": []})
    workspace.ask(identifier, "heavy", identifier)
    workspace.grant("heavy")
    workspace.ask(identifier, "heavy", identifier + "/next")
    answer = workspace.run("grant-next", kind="heavy", expect=3)
    assert answer["holders"][0]["initiative"] == identifier and answer["holders"][0]["holder"] == identifier
    workspace.run("update", {"initiative": identifier, "source": "fixture", "state": "paused"})
    answer = workspace.run("grant-next", kind="heavy", expect=3)
    assert answer["waiting"][0]["initiative"] == identifier
    assert answer["waiting"][0]["reason"] == "initiative is paused"


@pytest.mark.parametrize("identifier", ["sk-runner", "asia-launch", "ghp-docs", "akia-sync"])
def test_workspace_mcp_overlap_keeps_ids_and_protocol_length_paths(tmp_path, identifier):
    from tests.integration.test_hierarchy_role_tools import Team

    built = Team(tmp_path)
    first, second = clone_pair(tmp_path)
    built.workspace.register(identifier, checkouts=[str(first)])
    built.workspace.register("peer", checkouts=[str(second)])
    path = "src/" + "a" * 1017 + ".py"
    assert len(path) == 1024
    write_lease(second, identifier, [path])
    response = built.responses("a/lane/f2", [("workspace_path_overlap", {"paths": [path]})],
                               initiative=identifier)[-1]["result"]
    assert not response.get("isError", False)
    result = json.loads(response["content"][0]["text"])
    assert result["conflict"] is True and result["initiative"] == identifier
    assert result["paths"] == [fingerprint(path)]
    assert result["conflicts"][0]["lane"] == identifier
    assert result["conflicts"][0]["paths"] == [fingerprint(path)]


@pytest.mark.parametrize("prefix", ["", "prefix "], ids=["single-atom", "with-head"])
def test_workspace_display_bounds_input_before_unicode_expansion(prefix):
    value = prefix + "\ufdfa" * 87000
    with pytest.raises(ValueError) as error:
        controller.Ledger().initiative(value)
    assert str(error.value) == "initiative is not registered: " + fingerprint(value)


def test_workspace_byte_budget_cannot_expose_a_partial_credential():
    budget = 8 * controller.MAX_DISPLAY
    prefix = b"prefix " + "\u200b".encode("utf-8") * ((budget - len(b"prefix ") - 12) // 3)
    value = prefix + b"ghp_" + b"A" * 20 + b"\xff"
    assert len(value) > budget
    with pytest.raises(ValueError) as error:
        controller.Ledger().initiative(value)
    assert str(error.value) == "initiative is not registered: " + fingerprint(value)


def test_workspace_evidence_keeps_oserror_diagnostic(workspace, monkeypatch):
    def refuse(path):
        raise controller._Refusal("permission denied") from PermissionError(errno.EACCES, "fixture permission error")

    monkeypatch.setattr(controller, "safe_path", refuse)
    with pytest.raises(ValueError) as error:
        controller.verify_evidence({"path": str(workspace.tmp / "token=SYNTHETIC-S1"), "sha256": "a" * 64})
    assert str(error.value).startswith("terminal evidence is unavailable: ")
    assert "SYNTHETIC" not in str(error.value)


def test_workspace_lock_wrapper_never_owns_raw_descriptor(workspace, monkeypatch):
    modes = []

    def fdopen(descriptor, mode, **kwargs):
        modes.append(kwargs.get("closefd", True))
        return os.fdopen(descriptor, mode, **kwargs)

    monkeypatch.setattr(controller, "os", SimpleNamespace(**{**vars(os), "fdopen": fdopen}))
    with controller.Store(workspace.store).lock():
        pass
    assert modes == [False]


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode denial required")
def test_workspace_evidence_permission_denial_keeps_unavailable_refusal(workspace):
    if os.geteuid() == 0:
        pytest.skip("root bypasses directory mode denial")
    sealed = workspace.tmp / "sealed"
    sealed.mkdir()
    evidence = sealed / "token=SYNTHETIC-S1"
    evidence.write_bytes(b"fixture")
    sealed.chmod(0)
    try:
        with pytest.raises(ValueError) as error:
            controller.verify_evidence({"path": str(evidence), "sha256": "a" * 64})
        assert str(error.value).startswith("terminal evidence is unavailable: ")
        assert "SYNTHETIC" not in str(error.value)
    finally:
        sealed.chmod(0o700)


@pytest.mark.parametrize("failure", ["exception", "unreadable"])
def test_workspace_checkout_refusals_keep_protocol_length_paths(workspace, monkeypatch, failure):
    checkout = str(workspace.tmp / ("a" * 1024))
    workspace.register("a1", checkouts=[checkout])
    match, team, paths = controller.lease_tools()

    def read_leases(path):
        if failure == "exception":
            raise ValueError("fixture unavailable")
        return SimpleNamespace(leases=[], unreadable=[SimpleNamespace(lane="lane", oid="a" * 40,
                                                                       error="fixture unreadable")])

    reader = SimpleNamespace(glob_problem=team.glob_problem, read_leases=read_leases)
    monkeypatch.setattr(controller, "lease_tools", lambda: (match, reader, paths))
    code, result = controller.check_paths(controller.Store(workspace.store).load(), "a1", ["a.py"])
    assert code == 3
    rows = result["unreadable_checkouts"] if failure == "exception" else result["conflicts"]
    assert rows[0]["checkout"] == fingerprint(checkout)


@pytest.mark.parametrize("field", ["blocked_by", "request_id"])
def test_workspace_unvalidated_blocker_and_event_request_text_is_displayed(workspace, field):
    workspace.register("a1", blocked_by=["token=SYNTHETIC-S1"] if field == "blocked_by" else [])
    if field == "blocked_by":
        code, result = controller.check_delivery(controller.Store(workspace.store).load(), "a1")
        assert code == 3 and "SYNTHETIC" not in json.dumps(result)
        return
    request_id = workspace.ask("a1", "heavy")
    event = event_files(workspace)[-1]
    document = json.loads(event.read_text())
    assert document["data"]["request_id"] == request_id
    document["data"]["request_id"] = "token=SYNTHETIC-S1"
    event.write_text(json.dumps(document))
    workspace.grant("heavy")
    workspace.ask("a1", "heavy", "next")
    code, result = controller.grant_next(controller.Store(workspace.store), "heavy")
    assert code == 3 and "SYNTHETIC" not in json.dumps(result)


def test_workspace_known_cli_refusal_preserves_validated_identifier(workspace):
    identifier = "sk-" + "a" * 24
    workspace.register(identifier)
    workspace.run("update", {"initiative": identifier, "state": "paused", "source": "fixture"})
    result = subprocess.run(workspace.argv("request", {"initiative": identifier, "kind": "writer", "holder": "fixture"}),
                            capture_output=True, timeout=30)
    assert result.returncode == 2 and result.stderr == b""
    assert json.loads(result.stdout) == {"error": "initiative is not active: " + identifier}


def assert_path_refusal_fingerprints_raw_value(workspace, value):
    value = "../" + value
    workspace.register("a1")
    ledger = controller.Store(workspace.store).load()
    # Echoed refusal slots still fingerprint the entire original value. Path
    # validation itself now uses the claim's trusted, non-echoing diagnostic.
    with pytest.raises(ValueError) as error:
        controller.check_paths(ledger, value, [value])
    assert str(error.value) == "initiative is not registered: " + fingerprint(value)
    with pytest.raises(ValueError) as error:
        controller.check_paths(ledger, "a1", [value])
    expected = {"error": claim_path_refusal(workspace, [value])}
    assert str(error.value) == expected["error"]
    result = subprocess.run(workspace.argv("check-paths", {"initiative": "a1", "paths": [value]}),
                            capture_output=True, timeout=30)
    assert result.returncode == 2 and result.stderr == b""
    assert b"SYNTHETIC" not in result.stdout
    assert result.stdout == (json.dumps(expected, sort_keys=True) + os.linesep).encode("utf-8")


_AUTH_SCHEMES = ["Bearer", "Basic", "Digest", "Token", "Negotiate"]
_SEPARATORS = [pytest.param("\t", id="tab"), pytest.param("\r", id="cr"),
               pytest.param("\n", id="lf"), pytest.param(" ", id="space")]


@pytest.mark.parametrize("scheme", _AUTH_SCHEMES)
@pytest.mark.parametrize("separator", _SEPARATORS)
def test_workspace_scheme_separators_fingerprint_whole_raw_path(workspace, scheme, separator):
    assert_path_refusal_fingerprints_raw_value(workspace, "/" + scheme + separator + "SYNTHETIC_OPAQUE_1234567890")


@pytest.mark.parametrize("key", ["password", "passwd", "pwd", "secret", "token", "api key", "private key"])
@pytest.mark.parametrize("separator", _SEPARATORS)
@pytest.mark.parametrize("position", ["before-is", "after-is", "both"])
def test_workspace_prose_separators_fingerprint_whole_raw_path(workspace, key, separator, position):
    before = separator if position in ("before-is", "both") else " "
    after = separator if position in ("after-is", "both") else " "
    assert_path_refusal_fingerprints_raw_value(workspace, "/the " + key + before + "is" + after + "SYNTHETIC_PASSWORD")


@pytest.mark.parametrize("scheme", _AUTH_SCHEMES)
@pytest.mark.parametrize("size", [513, 1025, 1536])
def test_workspace_oversize_scheme_fingerprints_tail_too(workspace, scheme, size):
    assert_path_refusal_fingerprints_raw_value(workspace, "/" + scheme + " " + "A" * size + "SYNTHETIC_TAIL")


@pytest.mark.parametrize("scheme", _AUTH_SCHEMES)
@pytest.mark.parametrize("label,token,credential", _CREDENTIAL_CORPUS[6:7] + _CREDENTIAL_CORPUS[10:],
                         ids=[row[0] for row in _CREDENTIAL_CORPUS[6:7] + _CREDENTIAL_CORPUS[10:]])
def test_workspace_embedded_tokens_cannot_expose_scheme_suffix(workspace, scheme, label, token, credential):
    assert_path_refusal_fingerprints_raw_value(workspace, "/" + scheme + " " + token + "/SYNTHETIC_SUFFIX")


@pytest.mark.parametrize("value", [
    "/clean/./File_01.py:part-", "/" + "a" * 252, "/" + "a" * 253,
    "/clean path", "/clean\tpath", "/clean=path", '/clean"path', "/clean[path]",
    "/ｃｌｅａｎ/path", "/clean\x1b[31mpath", "/clean\u200bpath", "/clean\udcffpath",
    "/clean'path", "/clean@path", "/clean%path", "/clean\\path", "/clean;path", "/clean#path", "/clean&path",
    "/" + "*" * 252, "/" + "*" * 253,
], ids=["clean", "limit", "over-limit", "space", "tab", "equals", "quote", "brackets",
        "nfkc", "ansi", "format", "surrogate", "single-quote", "at", "percent", "backslash", "semicolon",
        "hash", "ampersand", "glob-limit", "glob-over-limit"])
def test_workspace_refusal_echoes_only_unchanged_conservative_paths(workspace, value):
    value = "../" + value
    workspace.register("a1")
    expected = value if len(value) <= 256 and value.isascii() and all(
        char.isalnum() or char in "/._-:*?[]{},!" for char in value) else fingerprint(value)
    ledger = controller.Store(workspace.store).load()
    with pytest.raises(ValueError) as error:
        controller.check_paths(ledger, value, [value])
    assert str(error.value) == "initiative is not registered: " + expected
    assert workspace.run("check-paths", {"initiative": value, "paths": [value]}, expect=2) == {
        "error": "initiative is not registered: " + expected}
    refusal = claim_path_refusal(workspace, [value])
    with pytest.raises(ValueError) as error:
        controller.check_paths(ledger, "a1", [value])
    assert str(error.value) == refusal
    assert workspace.run("check-paths", {"initiative": "a1", "paths": [value]}, expect=2) == {"error": refusal}


@pytest.mark.parametrize("checkout_component", ["checkout", "checkout with space"])
def test_workspace_json_conflict_fingerprints_each_raw_slot_once(workspace, monkeypatch, capsys, checkout_component):
    value = "sk_live_" + "A" * 16 + "/SYNTHETIC_SUFFIX"
    checkout_path = workspace.tmp / checkout_component
    checkout_path.mkdir()
    workspace.register("a1", checkouts=[str(checkout_path)])
    match, team, paths = controller.lease_tools()
    lease = SimpleNamespace(lane=value, oid="a" * 40, paths=[value], path_set=paths.stored_paths([value]),
                            owner=value, expired=lambda now: False, expires_at=123)
    bad = SimpleNamespace(lane=value, oid="b" * 40, error=value)
    reader = SimpleNamespace(glob_problem=team.glob_problem,
                             read_leases=lambda path: SimpleNamespace(leases=[lease], unreadable=[bad]))
    monkeypatch.setattr(controller, "lease_tools", lambda: (match, reader, paths))
    assert controller.main(workspace.argv("check-paths", {"initiative": "a1", "paths": [value]})[3:]) == 3
    captured = capsys.readouterr()
    assert captured.err == "" and "SYNTHETIC" not in captured.out
    result = json.loads(captured.out)
    assert result["paths"] == [fingerprint(value)]
    assert result["conflicts"][0]["lane"] == fingerprint(value)
    assert result["conflicts"][0]["owner"] == fingerprint(value)
    assert result["conflicts"][0]["paths"] == [fingerprint(value)]
    assert result["conflicts"][1]["lane"] == fingerprint(value)
    assert result["conflicts"][1]["unreadable"] == fingerprint(value)
    checkout = str(checkout_path)
    displayed_checkout = controller._display(checkout)
    if " " in checkout:
        assert displayed_checkout == fingerprint(checkout)
    assert [row["checkout"] for row in result["conflicts"]] == [displayed_checkout] * 2


def test_workspace_long_initiative_cli_fingerprints_the_complete_raw_value(workspace):
    value = "/" + " " * 4084 + "token=SYN\nTHETIC-S1"
    assert len(value) > 4096
    result = subprocess.run(workspace.argv("check-delivery", initiative=value), capture_output=True, timeout=30)
    assert result.returncode == 2 and result.stderr == b""
    assert b"SYN" not in result.stdout and b"THETIC" not in result.stdout
    expected = {"error": "initiative is not registered: " + fingerprint(value)}
    assert result.stdout == (json.dumps(expected, sort_keys=True) + os.linesep).encode("utf-8")


def detector_parity_samples():
    values = [value for _, value, _ in _CREDENTIAL_CORPUS]
    values += ["src/**", "docs/{a,b}/*.md", "tests/[ab]?_x.py", "!vendor/**", "", "src/file.py",
               "src/" + "a" * 252, "C:/src/file.py", "src/authorship:clean", "src/auth:SYNTHETIC_CREDENTIAL",
               "src/" + "x" * 33 + "token:SYNTHETIC_CREDENTIAL", "a" * 256,
               "src/Bearer\tSYNTHETIC_CREDENTIAL", "the password\nis\nSYNTHETIC_PASSWORD",
               "https://fixture:SYNTHETIC_PASSWORD@example.test/path"]
    rng = random.Random(2021)
    alphabet = "abcXYZ0123/._-:*?[]{},!"
    for _ in range(200):
        value = "".join(rng.choice(alphabet) for _ in range(rng.randrange(257)))
        values += [value, value + "token:SYNTHETIC_CREDENTIAL"]
    return values


_DETECTOR_PARITY_SAMPLES = detector_parity_samples()


@pytest.mark.parametrize("value", _DETECTOR_PARITY_SAMPLES,
                         ids=["sample-%d" % index for index in range(len(_DETECTOR_PARITY_SAMPLES))])
def test_workspace_detector_decisions_match_original_grammar(value):
    reference = tuple(re.compile(pattern.pattern.replace(r"(?<![A-Za-z0-9])", ""))
                      for pattern, _, _ in controller._SECRET_REDACTIONS) + (
        re.compile(r"(?i)(Bearer|Basic|Digest|Token|Negotiate)(\s{1,8})[A-Za-z0-9._~+/=-]{4,512}"),)
    matched = any(pattern.search(value) for pattern in reference)
    assert any(pattern.search(value) for pattern in controller._DISPLAY_CREDENTIALS) is matched
    assert controller._credential_match(value) is matched
    allowlisted = re.fullmatch(r"[A-Za-z0-9/._:*?\[\]{},!-]*", value) is not None
    expected = value if len(value) <= 256 and allowlisted and not matched else fingerprint(value)
    with pytest.raises(ValueError) as error:
        controller.Ledger().initiative(value)
    assert str(error.value) == "initiative is not registered: " + expected


def test_workspace_clean_conflict_paths_have_bounded_display_cost(workspace, monkeypatch):
    workspace.register("a1", checkouts=[str(workspace.tmp)])
    match, team, paths = controller.lease_tools()
    clean = []
    for index in range(256):
        prefix, suffix = "src/%03d/" % index, "/file.py"
        clean.append(prefix + "a" * (256 - len(prefix) - len(suffix)) + suffix)
    parsed = paths.stored_paths(clean)
    leases = [SimpleNamespace(lane="lane-%d" % index, oid="%040x" % index, paths=clean, path_set=parsed,
                              owner="fixture", expired=lambda now: False, expires_at=123)
              for index in range(100)]
    reader = SimpleNamespace(glob_problem=team.glob_problem,
                             read_leases=lambda path: SimpleNamespace(leases=leases, unreadable=[]))
    monkeypatch.setattr(controller, "lease_tools", lambda: (match, reader, paths))
    ledger = controller.Store(workspace.store).load()
    started = time.perf_counter()
    code, result = controller.check_paths(ledger, "a1", ["src/**"])
    elapsed = time.perf_counter() - started
    assert code == 3 and len(result["conflicts"]) == 100
    assert sum(len(row["paths"]) for row in result["conflicts"]) == 25600
    assert all(row["paths"] == clean for row in result["conflicts"])
    assert elapsed < 20, "25,600 clean paths exceeded the generous 20-second guard: %.3fs" % elapsed


@pytest.mark.parametrize("value", [
    "/the password\nis SYNTHETIC_PASSWORD",
    "/" + "x" * 33 + "token=SYNTHETIC_PASSWORD",
    "/Authorization:Bearer SYNTHETIC:OPAQUE_1234567890",
    "/authorization=Bearer SYNTHETIC:OPAQUE_1234567890",
    "/Bearer SYNTHETIC:OPAQUE_1234567890",
], ids=["prose-boundary", "assignment-prefix-33", "colon-header", "colon-assignment", "colon-bearer"])
def test_workspace_argon_variants_fingerprint_the_complete_raw_path(workspace, value):
    assert_path_refusal_fingerprints_raw_value(workspace, value)


@pytest.mark.parametrize("glob", ["src/**", "docs/{a,b}/*.md", "tests/[ab]?_x.py", "!vendor/**"])
def test_workspace_clean_globs_echo_unchanged_in_cli_refusal_and_conflict(workspace, glob):
    workspace.register("a1")
    invalid = "../" + glob
    refused = workspace.run("check-paths", {"initiative": "a1", "paths": [invalid]}, expect=2)
    assert refused == {"error": claim_path_refusal(workspace, [invalid])}
    echoed = workspace.run("check-paths", {"initiative": invalid, "paths": [invalid]}, expect=2)
    assert echoed == {"error": "initiative is not registered: " + invalid}
    workspace.register("owner", touched_paths=[glob])
    request_id = workspace.ask("owner")
    workspace.grant()
    report = workspace.run("check-paths", {"initiative": "a1", "paths": [glob]}, expect=3)
    assert report["paths"] == [glob]
    assert report["reserved_conflicts"] == [{"request_id": request_id, "initiative": "owner",
                                              "holder": "owner/lane", "paths": [glob]}]


@pytest.mark.parametrize("label,token,credential", _CREDENTIAL_CORPUS[6:7] + _CREDENTIAL_CORPUS[10:],
                         ids=[row[0] for row in _CREDENTIAL_CORPUS[6:7] + _CREDENTIAL_CORPUS[10:]])
def test_workspace_token_globs_fingerprint_whole_in_cli_refusal_and_conflict(workspace, label, token, credential):
    glob = "src/*/" + token + "/**"
    assert_path_refusal_fingerprints_raw_value(workspace, "/" + glob)
    workspace.register("owner", touched_paths=[glob])
    request_id = workspace.ask("owner")
    workspace.grant()
    report = workspace.run("check-paths", {"initiative": "a1", "paths": [glob]}, expect=3)
    assert report["paths"] == [fingerprint(glob)]
    assert report["reserved_conflicts"] == [{"request_id": request_id, "initiative": "owner",
                                              "holder": "owner/lane", "paths": [fingerprint(glob)]}]
    raw = json.dumps(report)
    assert credential not in raw and "SYNTHETIC" not in raw
