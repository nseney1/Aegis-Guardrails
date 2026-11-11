"""Workspace supersede and record-derived timing through the controller's public surfaces."""
import copy
import json
import os
import subprocess

import pytest

from tools import hierarchy_workspace as controller
from tests.integration.test_hierarchy_workspace import event_files, workspace


def snapshot(space):
    return {p.name: p.read_bytes() for p in event_files(space)}


def replace(space, old, **changes):
    return space.run("request", {"initiative": "a1", "kind": "heavy", "holder": "same",
                                 "supersedes": old, **changes})["request"]["request_id"]


@pytest.mark.parametrize("kind", ["writer", "heavy", "heavy-tests"])
def test_supersede_is_one_event_replays_and_inherits_queue_position(workspace, kind):
    workspace.register("a1")
    old = workspace.ask("a1", kind, "same")
    other = workspace.ask("a1", kind, "other")
    before = snapshot(workspace)
    original = controller.Store(workspace.store).load().requests[old]
    new = replace(workspace, old, kind=kind, reference="new tree")
    after = snapshot(workspace)
    assert len(after) == len(before) + 1
    assert {k: after[k] for k in before} == before
    event = json.loads(next(v for k, v in after.items() if k not in before))
    assert event["schema"] == "aegis.hierarchy-workspace-event/v2"
    assert event["kind"] == "request" and event["data"]["supersedes"] == old
    first = controller.Store(workspace.store).load()
    assert first.requests[old]["state"] == "withdrawn"
    assert first.requests[old]["superseded_by"] == new
    assert first.requests[old]["closed_at"] == first.requests[new]["requested_at"]
    assert first.requests[new]["seq"] == original["seq"]
    assert first.requests[new]["reference"] == "new tree"
    assert first.requests == controller.Store(workspace.store).load().requests
    assert [r["request_id"] for r in workspace.run("status")["capacity"]["queue"]] == [new, other]
    assert workspace.grant(kind)["request_id"] == new


@pytest.mark.parametrize("case,error", [
    ("missing", "superseded request does not exist"),
    ("holder", "superseded request must have the same initiative, holder and kind"),
    ("initiative", "superseded request must have the same initiative, holder and kind"),
    ("kind", "superseded request must have the same initiative, holder and kind"),
    ("withdrawn", "superseded request is not queued"),
    ("released", "superseded request is not queued"),
    ("granted", None),
    ("paused", "initiative is not active: a1"),
])
def test_supersede_refusal_leaves_all_events_unchanged(workspace, case, error):
    workspace.register("a1")
    workspace.register("a2")
    old = workspace.ask("a1", "heavy", "same")
    changes = {}
    if case == "missing":
        old = "req-99999999"
    elif case in ("holder", "initiative", "kind"):
        changes[{"holder": "holder", "initiative": "initiative", "kind": "kind"}[case]] = {
            "holder": "other", "initiative": "a2", "kind": "writer"}[case]
    elif case == "withdrawn":
        workspace.run("withdraw", {"request_id": old, "source": "fixture"})
    elif case in ("granted", "released"):
        workspace.grant("heavy")
        if case == "released":
            workspace.release(old)
        else:
            error = old + " is granted: accepted work is never preempted; wait for its release"
    elif case == "paused":
        workspace.run("update", {"initiative": "a1", "state": "paused", "source": "fixture"})
    before = snapshot(workspace)
    refused = workspace.run("request", {"initiative": "a1", "kind": "heavy", "holder": "same",
                                        "supersedes": old, **changes}, expect=2)
    assert refused == {"error": error}
    assert snapshot(workspace) == before
    assert not (workspace.store / ".write.lock").exists()


@pytest.mark.parametrize("value", [None, [], {}, 1, "", "req-00000001\nsecret", "x" * 100000],
                         ids=["null", "list", "object", "integer", "empty", "multiline", "oversized"])
def test_untrusted_supersedes_is_bounded_and_never_echoed(workspace, value):
    workspace.register("a1")
    before = snapshot(workspace)
    result = workspace.run("request", {"initiative": "a1", "kind": "heavy", "holder": "same",
                                       "supersedes": value}, expect=2)
    assert result == {"error": "invalid supersedes"}
    assert snapshot(workspace) == before


def test_two_concurrent_supersedes_have_exactly_one_winner(workspace):
    workspace.register("a1")
    old = workspace.ask("a1", "heavy", "same")
    argv = workspace.argv("request", {"initiative": "a1", "kind": "heavy", "holder": "same", "supersedes": old})
    processes = [subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                 env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}) for _ in range(2)]
    results = [(p.communicate(timeout=30), p.returncode) for p in processes]
    assert sorted(code for _, code in results) == [0, 2]
    for (out, err), code in results:
        assert not err
        if code == 2:
            assert json.loads(out)["error"] in (
                "workspace store is busy; inspect an abandoned lock before retrying",
                "superseded request is not queued")
    assert len(workspace.run("status")["capacity"]["queue"]) == 1


def test_supersede_chain_keeps_position_but_not_initiative_priority(workspace):
    workspace.register("a1", priority=20)
    workspace.register("urgent", priority=1)
    old = workspace.ask("a1", "heavy", "same")
    other = workspace.ask("a1", "heavy", "other")
    new = replace(workspace, replace(workspace, old))
    urgent = workspace.ask("urgent", "heavy")
    assert [r["request_id"] for r in workspace.run("status")["capacity"]["queue"]] == [urgent, new, other]


def test_full_history_refuses_supersede_without_withdrawing_old_row(workspace, monkeypatch, capsys):
    workspace.register("a1")
    old = workspace.ask("a1", "heavy", "same")
    before = snapshot(workspace)
    monkeypatch.setattr(controller, "MAX_RECORDS", len(before))
    argv = workspace.argv("request", {"initiative": "a1", "kind": "heavy", "holder": "same", "supersedes": old})
    assert controller.main(argv[3:]) == 2
    assert json.loads(capsys.readouterr().out) == {"error": "workspace event history limit reached"}
    assert snapshot(workspace) == before
    assert controller.Store(workspace.store).load().requests[old]["state"] == "queued"
    assert not (workspace.store / ".write.lock").exists()


def test_legacy_request_event_and_report_fields_are_unchanged(workspace, monkeypatch):
    workspace.register("a1")
    request_id = workspace.ask("a1", "heavy", "same")
    event = json.loads(event_files(workspace)[-1].read_text())
    assert event == {"schema": "aegis.hierarchy-workspace-event/v1", "seq": 3, "at": event["at"],
                     "kind": "request", "data": {"request_id": request_id, "initiative": "a1",
                                                  "kind": "heavy", "holder": "same"}}
    ledger = controller.Store(workspace.store).load()
    now = "2026-11-11T12:00:00Z"
    monkeypatch.setattr(controller, "timestamp", lambda: now)
    expected = {"generated_by": "script", "generated_at": now, "capacity": controller.capacity_view(ledger),
                "initiatives": [{**controller.initiative_view(ledger, "a1"), "mailbox": None}]}
    result = controller.report(ledger)
    assert {k: result[k] for k in expected} == expected
    lines = controller.report_text(result).splitlines()
    assert len(lines) == len(controller.report_text(expected).splitlines()) + 3


def test_ordinary_jobs_enqueue_keeps_exact_v1_event_bytes(workspace):
    from tools import hierarchy_jobs as jobs

    workspace.register("a1")
    store = controller.Store(workspace.store)
    job = jobs.Job(workspace.store, store.load().initiative("a1"), {"message_id": "bl03-job"})
    assert jobs.enqueue(store, job, "heavy", 0) is None
    raw = event_files(workspace)[-1].read_bytes()
    expected = {"schema": "aegis.hierarchy-workspace-event/v1", "seq": 3,
        "at": json.loads(raw)["at"], "kind": "request", "data": {"request_id": "req-00000003",
        "initiative": "a1", "kind": "heavy", "holder": "job:a1/bl03-job", "reference": "a1/bl03-job"}}
    assert raw == json.dumps(expected, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"


def at(seconds):
    return "2026-11-11T12:%02d:%02dZ" % divmod(seconds, 60)


def timing_ledger(space, times):
    # Fixture timestamps only: no git history, wall-clock assertions or filesystem capability needed.
    for path, value in zip(event_files(space), times):
        event = json.loads(path.read_text())
        event["at"] = at(value)
        path.write_text(json.dumps(event))
    return controller.Store(space.store).load()


def test_report_timing_uses_records_counts_open_and_reports_null_without_grants(workspace, monkeypatch):
    workspace.register("a1")
    first = workspace.ask("a1", "heavy", "one")
    workspace.grant("heavy")
    workspace.release(first)
    workspace.ask("a1", "heavy", "two")
    workspace.grant("heavy")
    old = workspace.ask("a1", "heavy", "same")
    replace(workspace, old)
    withdrawn = workspace.ask("a1", "heavy", "gone")
    workspace.run("withdraw", {"request_id": withdrawn, "source": "fixture"})
    ledger = timing_ledger(workspace, [0, 0, 10, 20, 50, 55, 70, 80, 90, 95, 100])
    monkeypatch.setattr(controller, "timestamp", lambda: at(120))
    facts = controller.report(ledger)["queue_facts"]
    assert facts["heavy"] == {"queued": 1, "open": 2, "oldest_queued_seconds": 30,
        "queue_wait_seconds": {"count": 2, "p50": 12.5, "max": 15}, "busy_seconds": 80,
        "withdrawn_count": 2, "superseded_count": 1, "timing_unknown": 0}
    assert facts["writer"] == {"queued": 0, "open": 0, "oldest_queued_seconds": None,
        "queue_wait_seconds": {"count": 0, "p50": None, "max": None}, "busy_seconds": None,
        "withdrawn_count": 0, "superseded_count": 0, "timing_unknown": 0}
    assert facts["heavy-tests"] == facts["writer"]


@pytest.mark.parametrize("damage", ["skew", "future", "closed-before-grant"])
def test_invalid_timing_is_unknown_never_negative(workspace, monkeypatch, damage):
    workspace.register("a1")
    old = workspace.ask("a1", "heavy", "one")
    workspace.grant("heavy")
    workspace.release(old)
    ledger = timing_ledger(workspace, [0, 0, 10, 20, 30])
    if damage == "skew":
        ledger.requests[old]["granted_at"] = at(5)
    elif damage == "future":
        ledger.requests[old]["closed_at"] = at(50)
    else:
        ledger.requests[old]["closed_at"] = at(15)
    before = copy.deepcopy(ledger.requests)
    monkeypatch.setattr(controller, "timestamp", lambda: at(40))
    fact = controller.report(ledger)["queue_facts"]["heavy"]
    assert fact["timing_unknown"] == 1
    assert fact["queue_wait_seconds"] == {"count": 0, "p50": None, "max": None}
    assert fact["busy_seconds"] is None
    assert ledger.requests == before


def test_report_from_replayed_clock_skew_and_ungranted_queue(workspace, monkeypatch):
    workspace.register("a1")
    workspace.ask("a1", "heavy", "one")
    workspace.grant("heavy")
    workspace.ask("a1", "writer", "queued")
    timing_ledger(workspace, [0, 0, 20, 10, 25])
    monkeypatch.setattr(controller, "timestamp", lambda: at(40))
    facts = controller.report(controller.Store(workspace.store).load())["queue_facts"]
    assert facts["heavy"]["timing_unknown"] == 1
    assert facts["heavy"]["open"] == 1
    assert facts["heavy"]["busy_seconds"] is None
    assert facts["writer"]["oldest_queued_seconds"] == 15
    assert facts["writer"]["queued"] == facts["writer"]["open"] == 1
    assert facts["writer"]["queue_wait_seconds"] == {"count": 0, "p50": None, "max": None}


def test_v1_event_cannot_smuggle_supersede(workspace):
    workspace.register("a1")
    old = workspace.ask("a1", "heavy", "same")
    replace(workspace, old)
    path = event_files(workspace)[-1]
    event = json.loads(path.read_text())
    event["schema"] = "aegis.hierarchy-workspace-event/v1"
    path.write_text(json.dumps(event))
    assert "supersedes requires workspace event v2" in workspace.run("status", expect=2)["error"]


def damage_request_time(space, case, value):
    """Persist timing damage after constructing the history through the public CLI."""
    space.register("a1")
    old = space.ask("a1", "heavy", "same")
    if case in ("grant", "release"):
        space.grant("heavy")
    if case == "release":
        space.release(old)
    elif case == "withdraw":
        space.run("withdraw", {"request_id": old, "source": "fixture"})
    elif case == "supersede":
        replace(space, old)
    path = event_files(space)[-1]
    event = json.loads(path.read_text())
    event["at"] = value
    path.write_text(json.dumps(event))
    return old, path


@pytest.mark.parametrize("case", ["request", "grant", "release", "withdraw", "supersede"])
@pytest.mark.parametrize("report_format", ["json", "text"])
@pytest.mark.parametrize("bad_time", ["BL03-UNTRUSTED-TIMESTAMP-DO-NOT-ECHO", None, [],
    {"opaque": "BL03-UNTRUSTED-TIMESTAMP-DO-NOT-ECHO"}, 1, "x" * 100000],
    ids=["unparsable", "null", "list", "object", "integer", "oversized"])
def test_report_cli_classifies_persisted_bad_request_timing(workspace, case, report_format, bad_time):
    damage_request_time(workspace, case, bad_time)
    before = snapshot(workspace)
    raw = workspace.run("report", raw=True, format=report_format)
    assert "BL03-UNTRUSTED-TIMESTAMP-DO-NOT-ECHO" not in raw
    assert "x" * 1000 not in raw
    if report_format == "json":
        result = json.loads(raw)
        facts = result["queue_facts"]["heavy"]
        if case in ("request", "supersede"):
            assert result["capacity"]["queue"][0]["requested_at"] is None
    else:
        line = next(line for line in raw.splitlines() if line.startswith("heavy queue facts: "))
        facts = json.loads(line.split(": ", 1)[1])
    assert facts["timing_unknown"] == (2 if case == "supersede" else 1)
    assert facts["queue_wait_seconds"] == {"count": 0, "p50": None, "max": None}
    assert facts["busy_seconds"] is None
    assert facts["open"] == (1 if case in ("request", "grant", "supersede") else 0)
    assert facts["withdrawn_count"] == (1 if case in ("withdraw", "supersede") else 0)
    assert facts["superseded_count"] == (1 if case == "supersede" else 0)
    assert snapshot(workspace) == before
    refused = workspace.run("update", {"initiative": "a1", "priority": 3, "source": "fixture"}, expect=2)
    assert "invalid UTC timestamp" in refused["error"]
    assert snapshot(workspace) == before
    assert not (workspace.store / ".write.lock").exists()


@pytest.mark.parametrize("command", ["request", "grant-next", "withdraw", "release", "register", "update",
                                     "set-limits", "mark-merge", "clear-base-moved"])
def test_every_workspace_mutator_keeps_strict_timestamp_replay(workspace, command):
    old, _ = damage_request_time(workspace, "grant", "bad timestamp")
    evidence = workspace.evidence()
    bodies = {
        "request": {"initiative": "a1", "kind": "writer", "holder": "other"},
        "withdraw": {"request_id": old, "source": "fixture"},
        "release": {"request_id": old, "evidence": evidence},
        "register": {"id": "a2", "project": "aegis", "repository": "aegis", "priority": 3,
                     "target_branch": "develop"},
        "update": {"initiative": "a1", "priority": 3, "source": "fixture"},
        "set-limits": {"heavy_limit": 2, "source": "fixture"},
        "mark-merge": {"repository": "aegis", "branch": "develop", "commit": "a" * 40, "source": "fixture"},
        "clear-base-moved": {"initiative": "a1", "base_commit": "a" * 40,
                             "evidence": evidence, "source": "fixture"}}
    before = snapshot(workspace)
    flags = {"kind": "heavy"} if command == "grant-next" else {}
    assert "invalid UTC timestamp" in workspace.run(command, bodies.get(command), expect=2, **flags)["error"]
    assert snapshot(workspace) == before
    assert "invalid UTC timestamp" in workspace.run("status", expect=2)["error"]
    assert not (workspace.store / ".write.lock").exists()


@pytest.mark.parametrize("report_format", ["json", "text"])
@pytest.mark.parametrize("damage,error", [
    ("schema", "wrong event schema or sequence"), ("sequence", "wrong event schema or sequence"),
    ("extra", "unexpected fields: extra"), ("missing-data", "missing fields: data"),
    ("missing-at", "missing fields: at")])
def test_report_cli_preserves_structural_validation(workspace, report_format, damage, error):
    _, path = damage_request_time(workspace, "request", "bad timestamp")
    event = json.loads(path.read_text())
    if damage == "schema":
        event["schema"] = "aegis.hierarchy-workspace-event/v999"
    elif damage == "sequence":
        event["seq"] += 1
    elif damage == "extra":
        event["extra"] = 1
    else:
        del event[damage.removeprefix("missing-")]
    path.write_text(json.dumps(event))
    before = snapshot(workspace)
    assert error in workspace.run("report", format=report_format, expect=2)["error"]
    assert snapshot(workspace) == before


@pytest.mark.parametrize("report_format", ["json", "text"])
def test_report_cli_preserves_state_validation_after_unknown_timing(workspace, report_format):
    old, _ = damage_request_time(workspace, "grant", "bad timestamp")
    path = event_files(workspace)[-1]
    event = json.loads(path.read_text())
    event.update(seq=event["seq"] + 1, at=at(40), data={"request_id": old})
    (path.parent / ("%08d.json" % event["seq"])).write_text(json.dumps(event))
    before = snapshot(workspace)
    assert "request is not queued" in workspace.run("report", format=report_format, expect=2)["error"]
    assert snapshot(workspace) == before


@pytest.mark.parametrize("kind", ["init", "register"])
def test_report_cli_keeps_nonrequest_timestamps_strict(workspace, kind):
    workspace.register("a1")
    path = next(p for p in event_files(workspace) if json.loads(p.read_text())["kind"] == kind)
    event = json.loads(path.read_text())
    event["at"] = "bad timestamp"
    path.write_text(json.dumps(event))
    before = snapshot(workspace)
    assert "invalid UTC timestamp" in workspace.run("report", expect=2)["error"]
    assert snapshot(workspace) == before
