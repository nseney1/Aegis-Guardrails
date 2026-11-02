"""The workspace controller coordinates initiatives, shared capacity and leases across clones.

Git repositories and Aegis leases here are real. Initiative labels are fixtures: nothing
in this file observes a host session, and a simulated run proves no host behavior.
"""
import hashlib
import json
import os
from pathlib import Path
import random
import subprocess
import sys
import time

import pytest

from tests.integration.test_hierarchy_mailbox import ROOT, git, invoke, message
from tests.integration.test_hierarchy_scenario import aegis


CONTROLLER = ROOT / "tools" / "hierarchy_workspace.py"
COMMIT = "a" * 40
LATER_COMMIT = "b" * 40


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
        result = subprocess.run(self.argv(command, request, **flags), capture_output=True, text=True, timeout=30,
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
    workspace.register("aegis-47", priority=5, touched_paths=["tools/**"], checkouts=["/absolute/clone"])
    record = workspace.run("status")["initiatives"]["aegis-47"]
    assert record["priority"] == 5 and record["state"] == "active"
    assert record["touched_paths"] == ["tools/**"] and record["base_moved"] is None
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
            assert "workspace store is busy" in json.loads(stdout)["error"]
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


def test_a_real_lease_in_another_clone_conflicts_though_that_clone_cannot_see_it(workspace, two_clones):
    first, second = two_clones
    aegis(first, "team", "claim", "first-lane", "--paths", "src/a/**")
    assert aegis(second, "team", "list").get("leases", []) == []
    conflict = workspace.run("check-paths", {"initiative": "second", "paths": ["src/a/value.txt"]}, expect=3)
    assert conflict["conflict"] is True
    row = conflict["conflicts"][0]
    assert row["lane"] == "first-lane" and row["initiative"] == "first" and row["checkout"] == str(first)
    clear = workspace.run("check-paths", {"initiative": "second", "paths": ["src/b/**"]})
    assert clear["conflict"] is False and clear["conflicts"] == []


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


@pytest.mark.parametrize("paths,error", [
    (["/absolute/path"], "invalid path"), (["../escape"], "invalid path"), ([], "invalid paths"), ("tools/**", "invalid paths"),
])
def test_malformed_path_checks_are_refused(workspace, paths, error):
    workspace.register("first")
    assert error in workspace.run("check-paths", {"initiative": "first", "paths": paths}, expect=2)["error"]


def test_a_missing_lease_reader_is_a_clear_error(workspace, tmp_path):
    workspace.register("first")
    copy = tmp_path / "copied-tools"
    copy.mkdir()
    for name in ("hierarchy_mailbox.py", "hierarchy_workspace.py"):
        (copy / name).write_bytes((CONTROLLER.parent / name).read_bytes())
    request = tmp_path / "paths.json"
    request.write_text(json.dumps({"initiative": "first", "paths": ["x.txt"]}), encoding="utf-8")
    result = subprocess.run([sys.executable, "-I", str(copy / "hierarchy_workspace.py"), "--store", str(workspace.store),
                             "check-paths", "--request", str(request)], capture_output=True, text=True, timeout=20,
                            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert result.returncode == 2 and not result.stderr
    assert json.loads(result.stdout)["error"] == "the Aegis lease reader is unavailable from this checkout"


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


def test_five_initiatives_across_two_projects_keep_the_caps_and_the_priority_order(workspace):
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
