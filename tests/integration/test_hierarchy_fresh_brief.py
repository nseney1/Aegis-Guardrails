"""Fresh-thread briefs through the CLI; records remain inert claims."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
from types import SimpleNamespace

import pytest

from tests.integration.test_hierarchy_mailbox import ROOT, invoke, message, pilot, receipt_fixture  # noqa: F401
from tests.integration.test_hierarchy_handoff import active_writer, handoff
from tests.integration.test_hierarchy_host_plan import write_plan
from tests.integration.test_hierarchy_lifecycle import Ledger, SOURCE, raw_request, request, pytestmark as lifecycle_only
from tests.integration.test_hierarchy_small_change_admission import SmallChange
from tools.hierarchy_mailbox import Mailbox


TOOL = ROOT / "tools" / "hierarchy_fresh_brief.py"
SECTIONS = ("Role contract", "Approved scope", "Source identity", "Open obligations",
            "Dependencies", "Unread work", "Evidence references")
ENDPOINT = "a/lane/f2"
AS_OF = "2026-11-07T12:00:00Z"
secure_publication = pytest.mark.skipif(os.name != "posix", reason="secure brief publication requires POSIX dir_fd support")


def cli(*args, expect=0):
    proc = subprocess.run([sys.executable, "-I", "-B", str(TOOL), *map(str, args)],
                          capture_output=True, text=True, timeout=30,
                          env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert proc.returncode == expect, proc.stdout + proc.stderr
    assert not proc.stderr, proc.stderr
    return json.loads(proc.stdout)


def compose(root, endpoint=ENDPOINT, expect=0, **flags):
    argv = ["compose", "--root", root, "--initiative", "a", "--endpoint", endpoint]
    for key, value in flags.items():
        argv += ["--" + key.replace("_", "-"), value]
    return cli(*argv, expect=expect)


def sections(brief):
    result, current = {}, None
    for line in Path(brief["path"]).read_text(encoding="utf-8").splitlines():
        if line.startswith("## "):
            current = line[3:]
            result[current] = []
        elif line.startswith("- {"):
            result[current].append(json.loads(line[2:]))
    assert tuple(result) == SECTIONS
    return result


def files(root):
    return {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}


def ref(path):
    return {"path": str(path), "sha256": hashlib.sha256(Path(path).read_bytes()).hexdigest()}


@pytest.fixture
def records(pilot, tmp_path):  # noqa: F811
    root, old_brief = pilot
    ledger = Ledger(tmp_path)
    change = SmallChange(ledger)
    change.register()
    change.decide()
    change.admit()
    uncertain = ledger.ready(request("uncertain"))
    ledger.intent(uncertain)
    ledger.terminal(uncertain, outcome="unknown")
    ledger.publish(request("dependent", prerequisites=[change.value["id"]]))
    finished = ledger.ready(request("finished"))
    ledger.intent(finished, intent_id="finished-attempt")
    # The fixture's terminal helper deliberately uses attempt-1; use its public event method here.
    result = {"request_sha256": ledger.target(finished)["request_sha256"], "intent_id": "finished-attempt",
              "outcome": "passed", "exit_code": 0, "source": SOURCE, "evidence": ledger.evidence}
    ledger.event("terminal", actor=ledger.operator, result=raw_request(result), **ledger.target(finished))
    ledger.accepted_delivery(finished)
    invoke(root, "publish", message(kind="dispatch", brief=old_brief))
    invoke(root, "publish", message(identifier="woken-note", body="SECRET_TRANSCRIPT_DO_NOT_INLINE"))
    delivery = tmp_path / "delivery"
    wake = delivery / "wakes" / ENDPOINT / "wake.json"
    wake.parent.mkdir(parents=True)
    wake.write_text(json.dumps({"schema": "aegis.hierarchy-delivery-receipt/v1", "endpoint": ENDPOINT,
                               "host": "host-one", "session": ENDPOINT, "generation": 1,
                               "at": "2026-11-07T00:00:00Z", "message_ids": ["woken-note"],
                               "wake_id": "wake-1", "state": "started"}))
    return root, ledger, change, wake


@lifecycle_only
def test_all_seven_items_reference_reverifiable_durable_records(records):
    root, ledger, change, wake = records
    answer = compose(root)
    brief = answer["brief"]
    rows = sections(brief)
    assert all(rows.values())
    assert answer["entries"] == sum(map(len, rows.values())) <= 256
    for group in rows.values():
        for item in group:
            assert item["ref"] == ref(item["ref"]["path"])
    assert rows["Role contract"][0]["ref"] == ref(ROOT / "tools/hierarchy_templates/roles/lane.md")
    scope = json.dumps(rows["Approved scope"])
    assert change.value["paths"][0] in scope
    assert change.value["continuation"]["expires_at"] in scope
    assert change.plan["request"]["sha256"] in scope
    assert change.row()["small_change"]["registration"]["proposal"]["sha256"] in scope
    assert '"small_change_admit"' in scope and '"small_change_decision"' in scope
    assert json.dumps(change.value["source"], sort_keys=True) in json.dumps(rows["Source identity"], sort_keys=True)
    assert any(row.get("request_id") == "dependent" and row.get("prerequisite") == change.value["id"]
               for row in rows["Dependencies"])
    evidence = json.dumps(rows["Evidence references"])
    assert str(ledger.evidence_path) in evidence
    assert all('"event_type": "' + kind + '"' in evidence for kind in ("small_change_admit", "terminal", "review"))
    body = Path(brief["path"]).read_text()
    assert "Resume path:" in body and "reconcile" in body
    assert "SECRET_TRANSCRIPT_DO_NOT_INLINE" not in body
    assert hashlib.sha256(body.encode()).hexdigest() == brief["sha256"]
    assert brief["sha256"] in Path(brief["path"]).name
    assert Path(brief["path"]).parent == root.parent / "briefs"
    assert Mailbox(root).brief(brief, verify=True) == body.encode()
    assert cli("verify", "--path", brief["path"], "--sha256", brief["sha256"])["ok"] is True


@lifecycle_only
def test_unknown_effects_and_woken_unread_are_never_dropped(records):
    root, _, _, wake = records
    rows = sections(compose(root)["brief"])
    assert any(row.get("request_id") == "uncertain" and row.get("state") == "unknown_effect"
               for row in rows["Open obligations"])
    assert any(row.get("message_id") == "woken-note" and row.get("state") == "woken"
               for row in rows["Unread work"])
    assert ref(wake) in [row["ref"] for row in rows["Evidence references"]]


@lifecycle_only
def test_determinism_and_no_store_mutations(records):
    root, _, _, _ = records
    before = files(root.parent)
    first = compose(root, as_of=AS_OF)
    raw = Path(first["brief"]["path"]).read_bytes()
    after = files(root.parent)
    assert after.pop(str(Path(first["brief"]["path"]).relative_to(root.parent))) == raw
    assert after == before
    assert compose(root, as_of=AS_OF) == first
    assert Path(first["brief"]["path"]).read_bytes() == raw


@secure_publication
def test_exact_entry_bound_and_overflow_leave_no_partial_output(pilot):  # noqa: F811
    root, _ = pilot
    initial = compose(root)
    needed = 256 - initial["entries"]
    for index in range(needed):
        invoke(root, "publish", message(identifier="note-%03d" % index))
    at_bound = compose(root)
    assert at_bound["entries"] == 256
    assert len(sections(at_bound["brief"])["Unread work"]) == needed
    invoke(root, "publish", message(identifier="overflow"))
    before = files(root.parent)
    assert compose(root, expect=2)["error"] == "fresh brief exceeds 256 entries"
    assert files(root.parent) == before


@secure_publication
def test_corruption_refuses_verify_and_mailbox_read(pilot):  # noqa: F811
    root, _ = pilot
    brief = compose(root)["brief"]
    Path(brief["path"]).write_bytes(b"corrupted\n")
    assert cli("verify", "--path", brief["path"], "--sha256", brief["sha256"], expect=2)["error"] == "brief sha256 mismatch"
    with pytest.raises(ValueError, match="^brief sha256 mismatch$"):
        Mailbox(root).brief(brief, verify=True)


@secure_publication
def test_handoff_carries_brief_and_successor_pages_inbox_losslessly(pilot, tmp_path):  # noqa: F811
    root, _ = pilot
    identifiers = ["note-%03d" % i for i in range(105)]
    for identifier in identifiers:
        invoke(root, "publish", message(identifier=identifier))
    brief = compose(root)["brief"]
    assert [row["message_id"] for row in sections(brief)["Unread work"]] == identifiers
    result = handoff(tmp_path, {"schema": "aegis.hierarchy-handoff/v1", "host": "host-two",
                               "session": "successor", "outgoing_stopped": True,
                               "entries": [{"root": str(root), "endpoint": ENDPOINT, "briefs": [brief]}]}, 0)
    invoke(root, "ack-handoff", result["entries"][0]["acknowledge"])
    seen, cursor = [], None
    for _ in range(8):
        flags = {"after": cursor} if cursor else {}
        page = invoke(root, "inbox", endpoint=ENDPOINT, include_briefs=True, limit=17, **flags)
        assert page["checkpoint_briefs"][0]["sha256"] == brief["sha256"]
        seen += [row["message"]["message_id"] for row in page["messages"]]
        cursor = page["next_after"]
        if cursor is None:
            break
    assert cursor is None and seen == identifiers


@pytest.mark.parametrize("endpoint", [ENDPOINT, "a/lane/review", "a/orchestrator", "a/front-door"])
@secure_publication
def test_contract_matches_role_kind_and_host_family(pilot, endpoint):  # noqa: F811
    root, _ = pilot
    write_plan(SimpleNamespace(base=root.parent), hierarchy="a", team="claude-code", stand_ins={})
    answer = compose(root, endpoint)
    body = Path(answer["brief"]["path"]).read_text()
    rows = sections(answer["brief"])
    expected = {ENDPOINT: ["lane.md"], "a/lane/review": ["lane.md", "reviewer.md"],
                "a/orchestrator": ["orchestrator.md"], "a/front-door": ["front-door.md"]}[endpoint]
    assert [Path(item["ref"]["path"]).name for item in rows["Role contract"]] == expected
    assert all(item["family"] == "claude" for item in rows["Role contract"])
    assert "<!-- host:" not in body
    assert any(row["ref"] == ref(root.parent / "host-plan.json") for row in rows["Evidence references"])


@pytest.mark.parametrize("flags,error", [
    ({"endpoint": "b/front-door"}, "endpoint is outside initiative a"),
    ({"lifecycle": "missing"}, "lifecycle directory unavailable"),
])
def test_invalid_inputs_refuse_without_writing(pilot, flags, error):  # noqa: F811
    root, _ = pilot
    if flags.get("lifecycle") == "missing":
        flags = {"lifecycle": str(root.parent / "missing-lifecycle")}
    before = files(root.parent)
    assert error in compose(root, expect=2, **flags)["error"]
    assert files(root.parent) == before


@secure_publication
def test_verify_detects_changed_reference_even_with_unchanged_brief(pilot):  # noqa: F811
    root, _ = pilot
    brief = compose(root)["brief"]
    manifest = root / "manifest.json"
    manifest.write_bytes(manifest.read_bytes() + b"\n")
    assert "reference sha256 mismatch" in cli("verify", "--path", brief["path"], "--sha256", brief["sha256"], expect=2)["error"]


@secure_publication
def test_uncertain_jobs_keep_ids_hashes_and_v2_dependencies(tmp_path):
    root, _, _ = receipt_fixture(tmp_path)
    packet = tmp_path / "packet.md"
    packet.write_text(json.dumps({"schema": "aegis.hierarchy-job-packet/v2", "recipe": "tests",
                                 "checkout": str(tmp_path), "commit": "a" * 40, "tree": "b" * 40,
                                 "after": {"message_id": "prior", "sha256": "c" * 64},
                                 "recipes_sha256": "d" * 64}))
    original = invoke(root, "publish", message(recipient="a/root", identifier="uncertain-job",
                                               kind="job_request", brief=ref(packet)))
    invoke(root, "publish", message("a/root", "a/orchestrator", identifier="lost-reply", kind="job_receipt",
                                    in_reply_to="uncertain-job", receipt={"state": "unknown", "reason": "lost reply"}))
    before = files(tmp_path)
    brief = compose(root, "a/orchestrator")["brief"]
    rows = sections(brief)
    job = next(row for row in rows["Open obligations"] if row.get("job_id") == "a/uncertain-job")
    assert job["state"] == "unknown" and job["ref"] == ref(original["path"])
    assert any(row.get("after") == {"message_id": "prior", "sha256": "c" * 64} and row["ref"] == ref(packet)
               for row in rows["Dependencies"])
    assert any(row.get("source", {}).get("commit") == "a" * 40 for row in rows["Source identity"])
    after = files(tmp_path)
    after.pop(str(Path(brief["path"]).relative_to(tmp_path)))
    assert after == before


@secure_publication
def test_recorded_reads_are_excluded_but_no_delivery_history_is_conservative(tmp_path):
    root, delivery, _ = receipt_fixture(tmp_path, endpoint="a/root")
    invoke(root, "inbox", endpoint="a/root", delivery_dir=delivery, mark_read=True,
           host="host-one", session="a/root", generation=1)
    brief = compose(root, "a/root")["brief"]
    aggregate = sections(brief)["Unread work"]
    assert len(aggregate) == 1 and aggregate[0]["state"] == "read_by_predecessor" and aggregate[0]["count"] == 1
    assert "receipt-note" not in json.dumps(sections(brief)["Unread work"])
    assert any(row.get("kind") == "delivery_read" for row in sections(brief)["Evidence references"])


@secure_publication
def test_run_root_resolves_initiative_base_and_runtime_pin(pilot, tmp_path):  # noqa: F811
    root, _ = pilot
    base = tmp_path / "initiatives" / "a"
    base.mkdir(parents=True)
    root.rename(base / "mailbox")
    setup = {"initiative": "a", "mailbox_root": str(base / "mailbox"), "delivery_dir": str(base / "delivery"),
             "source": str(ROOT), "source_commit": "e" * 40, "source_tree": "f" * 40}
    (base / "provision.json").write_text(json.dumps(setup))
    answer = compose(tmp_path)
    assert Path(answer["brief"]["path"]).parent == base / "briefs"
    sources = sections(answer["brief"])["Source identity"]
    assert any(row.get("source_commit") == "e" * 40 and row["ref"] == ref(base / "provision.json") for row in sources)


@lifecycle_only
def test_malformed_journal_refuses_without_creating_a_briefs_folder(pilot, tmp_path):  # noqa: F811
    root, _ = pilot
    ledger = Ledger(tmp_path)
    ledger.publish()
    event = ledger.path / "events" / "000001.json"
    event.write_text("{}")
    before = files(tmp_path)
    assert "missing fields" in compose(root, expect=2)["error"]
    assert files(tmp_path) == before and not (tmp_path / "briefs").exists()


@pytest.mark.parametrize("argv", [[], ["compose"], ["verify", "--path", "relative.md"]])
def test_malformed_cli_answers_as_json(argv):
    assert "required" in cli(*argv, expect=2)["error"]


def test_malformed_structured_packet_refuses_instead_of_dropping_dependencies(tmp_path):
    root, _, _ = receipt_fixture(tmp_path)
    packet = tmp_path / "broken-packet.md"
    packet.write_text('{"schema":"aegis.hierarchy-job-packet/v2","after":')
    invoke(root, "publish", message(recipient="a/root", identifier="broken-job", kind="job_request", brief=ref(packet)))
    before = files(tmp_path)
    error = compose(root, "a/orchestrator", expect=2)["error"]
    assert str(packet) in error and "JSON" in error
    assert files(tmp_path) == before


@secure_publication
def test_failed_atomic_publication_leaves_no_brief_or_temporary_file(pilot):  # noqa: F811
    root, _ = pilot
    # Inject only at the OS boundary, then enter the actual CLI. No composer internals are replaced.
    driver = ("import os,runpy,sys\n"
              "def refuse(*args,**kwargs):\n    raise OSError('fixture replace refused')\n"
              "os.replace=refuse\n"
              "sys.argv=sys.argv[1:]\n"
              "runpy.run_path(sys.argv[0],run_name='__main__')\n")
    before = files(root.parent)
    proc = subprocess.run([sys.executable, "-I", "-B", "-c", driver, str(TOOL), "compose", "--root", str(root),
                           "--initiative", "a", "--endpoint", ENDPOINT], capture_output=True, text=True, timeout=15)
    assert proc.returncode == 3 and not proc.stderr
    assert json.loads(proc.stdout)["error"] == "brief publication failed: fixture replace refused"
    assert files(root.parent) == before
    assert list((root.parent / "briefs").iterdir()) == []


@lifecycle_only
@pytest.mark.parametrize("transition", ["disposition", "resolve"])
def test_next_request_origin_and_pending_obligation_are_the_creating_event(pilot, tmp_path, transition):  # noqa: F811
    root, _ = pilot
    ledger = Ledger(tmp_path)
    first, following = request("first"), request("successor")
    ledger.publish(first)
    if transition == "resolve":
        ledger.event("disposition", status="HOLD", resolution={"kind": "blocked", "owner": "coordinator-1",
                     "next_decision": "resume", "condition": "ready", "evidence": ledger.evidence}, **ledger.target(first))
        blocker = ledger.status()["requests"]["first"]["resolution"]
        extra = {"blocker_sha256": hashlib.sha256(json.dumps(blocker, sort_keys=True, separators=(",", ":")).encode()).hexdigest()}
    else:
        extra = {"status": "FINAL"}
    receipt = ledger.event(transition, resolution={"kind": "next", "request": raw_request(following),
                           "evidence": ledger.evidence}, **ledger.target(first), **extra)
    origin = ref(ledger.path / "events" / ("%06d.json" % receipt["sequence"]))
    before = files(tmp_path)
    answer = compose(root)
    rows = sections(answer["brief"])
    for section in ("Approved scope", "Source identity", "Open obligations"):
        items = [row for row in rows[section] if row.get("request_id") == "successor"]
        assert items and all(item["ref"] == origin for item in items)
    assert not any(row.get("request_id") == "first" for row in rows["Approved scope"])
    after = files(tmp_path)
    after.pop(str(Path(answer["brief"]["path"]).relative_to(tmp_path)))
    assert after == before


def completed_request(ledger, identifier):
    value = ledger.ready(request(identifier))
    intent = identifier + "-intent"
    ledger.intent(value, intent_id=intent)
    result = {"request_sha256": ledger.target(value)["request_sha256"], "intent_id": intent,
              "outcome": "passed", "exit_code": 0, "source": SOURCE, "evidence": ledger.evidence}
    terminal = raw_request(result)
    ledger.event("terminal", actor=ledger.operator, result=terminal, **ledger.target(value))
    ledger.event("review", actor="reviewer-1", result_sha256=terminal["sha256"], source=SOURCE,
                 verdict="accept", evidence=ledger.evidence, **ledger.target(value))
    ledger.event("delivery", evidence=ledger.evidence, **ledger.target(value))
    ledger.event("disposition", status="FINAL", resolution={"kind": "complete", "evidence": ledger.evidence},
                 **ledger.target(value))
    return value


@lifecycle_only
def test_forty_completed_requests_are_covered_by_one_head_without_consuming_the_bound(pilot, tmp_path):  # noqa: F811
    root, _ = pilot
    ledger = Ledger(tmp_path)
    for index in range(40):
        completed_request(ledger, "done-%02d" % index)
    before = files(tmp_path)
    answer = compose(root)
    rows = sections(answer["brief"])
    assert answer["entries"] < 20
    assert rows["Approved scope"] == rows["Open obligations"] == []
    heads = [row for row in rows["Evidence references"] if row["kind"] == "lifecycle_head"]
    assert len(heads) == 1
    assert heads[0]["ref"] == ref(ledger.path / "events" / ("%06d.json" % ledger.status()["sequence"]))
    after = files(tmp_path)
    after.pop(str(Path(answer["brief"]["path"]).relative_to(tmp_path)))
    assert after == before


@secure_publication
def test_257_genuinely_unread_messages_refuse_without_writing(pilot):  # noqa: F811
    root, _ = pilot
    for index in range(257):
        invoke(root, "publish", message(identifier="open-%03d" % index))
    before = files(root.parent)
    assert compose(root, expect=2)["error"] == "fresh brief exceeds 256 entries"
    assert files(root.parent) == before and not (root.parent / "briefs").exists()


@lifecycle_only
def test_expired_scope_is_history_but_its_unsettled_obligation_remains(pilot, tmp_path):  # noqa: F811
    root, _ = pilot
    ledger = Ledger(tmp_path)
    ledger.publish(request("expired", continuation={"members": [], "max_starts": 1, "expires_at": "2000-01-01T00:00:00Z"}))
    rows = sections(compose(root)["brief"])
    assert not any(row.get("request_id") == "expired" for row in rows["Approved scope"])
    assert any(row.get("request_id") == "expired" for row in rows["Open obligations"])


@secure_publication
def test_closed_dispatch_lease_and_missing_brief_are_history(pilot, tmp_path):  # noqa: F811
    root, old_brief, ready = active_writer(pilot, tmp_path)
    completion = invoke(root, "publish", message("a/lane/f2", "a/orchestrator", identifier="done", kind="result",
                                    in_reply_to="dispatch-1", result={"source_revision": ready["base_revision"],
                                    "source_tree": "b" * 40, "checks": [{"check": "tests", "outcome": "pass", "reference": "retained"}],
                                    "lane_check": "retained"}))
    Path(old_brief["path"]).unlink()
    answer = compose(root)
    rows = sections(answer["brief"])
    assert ready["lease_ref"] not in json.dumps(rows["Approved scope"])
    assert not rows["Open obligations"]
    history = [row for row in rows["Evidence references"] if row["kind"] == "mailbox_history"]
    assert len(history) == 1 and history[0]["ref"] == ref(completion["path"])
    assert history[0]["historical_briefs"] == "not_reverified"
    assert not any(row["ref"]["path"] == old_brief["path"] for row in rows["Evidence references"])


def job_history(tmp_path):
    root, _, _ = receipt_fixture(tmp_path)
    packet = tmp_path / "packet.md"
    packet.write_text(json.dumps({"schema": "aegis.hierarchy-job-packet/v1", "recipe": "tests",
                                 "checkout": str(tmp_path), "commit": "a" * 40, "tree": "b" * 40}))
    original = invoke(root, "publish", message(recipient="a/root", identifier="job", kind="job_request", brief=ref(packet)))
    unknown = invoke(root, "publish", message("a/root", "a/orchestrator", identifier="unknown", kind="job_receipt",
                                              in_reply_to="job", receipt={"state": "unknown", "reason": "lost reply"}))
    evidence = tmp_path / "job-result.json"
    evidence.write_text("{}\n")
    terminal = invoke(root, "publish", message("a/root", "a/orchestrator", identifier="terminal", kind="job_receipt",
                                               in_reply_to="job", receipt={"state": "completed", "exit_code": 0, "evidence": [ref(evidence)]}))
    return root, packet, original, unknown, terminal


def set_record_time(record, at):
    # Stored histories may order differently from publication; the reader validates this supported input.
    header = {**record["message"], "created_at": at}
    body = header.pop("body")
    Path(record["path"]).write_bytes(b"---\n" + json.dumps(header, sort_keys=True).encode() + b"\n---\n\n" + body.encode())


@secure_publication
def test_later_unknown_survives_an_earlier_terminal_until_a_correlated_later_terminal(tmp_path):
    root, packet, original, unknown, terminal = job_history(tmp_path)
    set_record_time(terminal, "2026-01-01T00:00:00Z")
    set_record_time(unknown, "2026-01-02T00:00:00Z")
    rows = sections(compose(root, "a/orchestrator")["brief"])
    assert any(row.get("job_id") == "a/job" and row.get("state") == "unknown" and row["ref"] == ref(original["path"])
               for row in rows["Open obligations"])
    # The same correlated terminal only settles the job when its durable timestamp is later.
    set_record_time(terminal, "2026-01-03T00:00:00Z")
    rows = sections(compose(root, "a/orchestrator")["brief"])
    assert not any(row.get("job_id") == "a/job" for row in rows["Open obligations"])


@secure_publication
@pytest.mark.parametrize("damage", ["missing", "changed"])
def test_historical_packets_do_not_block_but_uncertain_packets_do(tmp_path, damage):
    root, packet, original, unknown, terminal = job_history(tmp_path)
    set_record_time(unknown, "2026-01-01T00:00:00Z")
    set_record_time(terminal, "2026-01-02T00:00:00Z")
    if damage == "missing":
        packet.unlink()
    else:
        packet.write_text("changed\n")
    rows = sections(compose(root, "a/orchestrator")["brief"])
    history = [row for row in rows["Evidence references"] if row["kind"] == "mailbox_history"]
    assert len(history) == 1 and history[0]["ref"] == ref(original["path"])
    assert history[0]["historical_briefs"] == "not_reverified"
    assert not any(row["ref"]["path"] == str(packet) for row in rows["Evidence references"])
    set_record_time(unknown, "2026-01-03T00:00:00Z")
    before = files(tmp_path)
    error = compose(root, "a/orchestrator", expect=2)["error"]
    assert ("file unavailable" if damage == "missing" else "brief sha256 mismatch") in error
    assert files(tmp_path) == before


@secure_publication
def test_old_read_and_wake_history_is_bounded_and_successor_reads_are_generation_scoped(tmp_path):
    root, delivery, checkpoint = receipt_fixture(tmp_path, endpoint="a/root")
    invoke(root, "inbox", endpoint="a/root", delivery_dir=delivery, mark_read=True,
           host="host-one", session="a/root", generation=1)
    folder = delivery / "reads" / "a/root"
    receipt = json.loads(next(folder.iterdir()).read_text())
    for index in range(300):
        (folder / ("history-%03d.json" % index)).write_text(json.dumps(receipt))
    wakes = delivery / "wakes" / "a/root"
    wakes.mkdir(parents=True)
    for index in range(300):
        (wakes / ("history-%03d.json" % index)).write_text(json.dumps(
            {**receipt, "wake_id": "wake-%03d" % index, "state": "started"}))
    answer = compose(root, "a/root")
    assert answer["entries"] < 20
    before_bind = sections(answer["brief"])["Unread work"]
    assert len(before_bind) == 1 and before_bind[0]["state"] == "read_by_predecessor"
    invoke(root, "bind", {"endpoint": "a/root", "host": "host-two", "session": "successor", "expected_generation": 1,
                          "checkpoint": checkpoint})
    rows = sections(compose(root, "a/root")["brief"])
    assert len(rows["Unread work"]) == 1
    assert rows["Unread work"][0]["state"] == "read_by_predecessor" and rows["Unread work"][0]["count"] == 1


@secure_publication
def test_json_answer_reports_absent_lifecycle_coverage(pilot):  # noqa: F811
    root, _ = pilot
    assert compose(root)["coverage"]["lifecycle"] == "absent"


def faulted_cli(root, driver, timeout=30):
    proc = subprocess.run([sys.executable, "-I", "-B", "-c", driver, str(TOOL), str(root)],
                          capture_output=True, text=True, timeout=timeout,
                          env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert not proc.stderr, proc.stderr
    return proc.returncode, json.loads(proc.stdout)


@secure_publication
@pytest.mark.parametrize("boundary", ["create", "rename"])
def test_publication_directory_swap_never_writes_into_a_store(pilot, boundary):  # noqa: F811
    root, _ = pilot
    briefs, held, store = root.parent / "briefs", root.parent / "held-briefs", root.parent / "store"
    briefs.mkdir()
    store.mkdir()
    sentinel = store / "sentinel"
    sentinel.write_text("store must stay unchanged")
    driver = ("import os,runpy,sys\nfrom pathlib import Path\n"
              "tool,root=sys.argv[1:]\nbase=Path(root).parent\n"
              "real_open,real_replace=os.open,os.replace\nswapped=False\n"
              "def swap():\n"
              "    global swapped\n"
              "    if not swapped:\n"
              "        swapped=True\n"
              "        os.rename(base/'briefs',base/'held-briefs')\n"
              "        os.symlink(base/'store',base/'briefs',target_is_directory=True)\n"
              "def opening(path,flags,*args,**kwargs):\n"
              + ("    if str(path).split('/')[-1].startswith('.fresh-') and flags & os.O_CREAT: swap()\n" if boundary == "create" else "")
              + "    return real_open(path,flags,*args,**kwargs)\n"
              "def replacing(src,dst,*args,**kwargs):\n"
              + ("    swap()\n" if boundary == "rename" else "")
              + "    return real_replace(src,dst,*args,**kwargs)\n"
              "os.open,os.replace=opening,replacing\n"
              "sys.argv=[tool,'compose','--root',root,'--initiative','a','--endpoint','a/lane/f2']\n"
              "runpy.run_path(tool,run_name='__main__')\n")
    before = files(store)
    code, answer = faulted_cli(root, driver)
    assert files(store) == before, "publication followed the swapped symlink into a store"
    assert code == 2 and "publication directory changed" in answer["error"]
    assert list(held.iterdir()) == []


def test_unsupported_dir_fd_refuses_cleanly_before_creating_any_output(pilot):  # noqa: F811
    root, _ = pilot
    driver = ("import os,runpy,sys\n"
              "tool,root=sys.argv[1:]\nos.supports_dir_fd=set()\n"
              "sys.argv=[tool,'compose','--root',root,'--initiative','a','--endpoint','a/lane/f2']\n"
              "runpy.run_path(tool,run_name='__main__')\n")
    before = files(root.parent)
    code, answer = faulted_cli(root, driver)
    assert code == 2 and answer["error"] == "secure brief publication requires directory descriptor support"
    assert files(root.parent) == before and not (root.parent / "briefs").exists()


def test_byte_limit_refuses_without_writing(pilot):  # noqa: F811
    root, _ = pilot
    source = root.parent / "source"
    templates = source / "tools/hierarchy_templates"
    (templates / "roles").mkdir(parents=True)
    shutil.copyfile(ROOT / "tools/hierarchy_templates/lane-brief.md", templates / "lane-brief.md")
    (templates / "roles/lane.md").write_text("# Role\n" + "x" * 262144)
    (root.parent / "provision.json").write_text(json.dumps({"initiative": "a", "source": str(source),
        "mailbox_root": str(root), "delivery_dir": str(root.parent / "delivery")}))
    before = files(root.parent)
    assert compose(root, expect=2)["error"] == "fresh brief exceeds mailbox brief byte limit (262144)"
    assert files(root.parent) == before and not (root.parent / "briefs").exists()


def test_verify_portable_brief_without_a_journal_or_publication(tmp_path):
    manifest = tmp_path / "record.json"
    manifest.write_text("{}\n")
    brief = tmp_path / "brief.md"
    body = ["# Fresh thread brief", "<!-- aegis.hierarchy-fresh-brief/v1 -->", "Resume path: Verify first."]
    for name in SECTIONS:
        body += ["## " + name, "- " + json.dumps({"kind": "record", "ref": ref(manifest)})]
    brief.write_text("\n".join(body) + "\n")
    reference = ref(brief)
    assert cli("verify", "--path", brief, "--sha256", reference["sha256"])["ok"] is True


def provision_record(root, **changes):
    value = {"initiative": "a", "source": str(ROOT), "mailbox_root": str(root),
             "delivery_dir": str(root.parent / "delivery"), **changes}
    (root.parent / "provision.json").write_text(json.dumps(value))
    return value


@secure_publication
def test_output_cannot_be_the_mailbox_store(pilot):  # noqa: F811
    root, _ = pilot
    destination = root.parent / "briefs"
    root.rename(destination)
    before = files(destination.parent)
    assert "output directory overlaps coordination store" in compose(destination, expect=2)["error"]
    assert files(destination.parent) == before


@pytest.mark.parametrize("store_kind", ["delivery", "store", "board", pytest.param("lifecycle", marks=lifecycle_only)])
@pytest.mark.parametrize("relation", ["equal", "inside", "around"])
def test_output_refuses_overlap_with_every_declared_coordination_store(pilot, tmp_path, store_kind, relation):  # noqa: F811
    root, _ = pilot
    output = tmp_path / "briefs"
    store = {"equal": output, "inside": tmp_path, "around": output / "nested-store"}[relation]
    flags = {}
    if store_kind == "lifecycle":
        staging = tmp_path / "staging"
        staging.mkdir()
        ledger = Ledger(staging)
        shutil.copytree(ledger.path, store, dirs_exist_ok=True)
        flags["lifecycle"] = str(store)
    else:
        store.mkdir(parents=True, exist_ok=True)
        provision_record(root, **{("delivery_dir" if store_kind == "delivery" else store_kind): str(store)})
        # A command-line override must not stop protecting the provisioned delivery store.
        flags["delivery_dir"] = str(tmp_path / "safe-delivery")
    before = files(tmp_path)
    assert "output directory overlaps coordination store" in compose(root, expect=2, **flags)["error"]
    assert files(tmp_path) == before


@secure_publication
@pytest.mark.parametrize("record_path", ["initiatives/other/provision.json", "evidence/provision-init.json"])
def test_store_named_by_another_run_record_is_also_protected(pilot, tmp_path, record_path):  # noqa: F811
    root, _ = pilot
    path = tmp_path / record_path
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"store": str(tmp_path / "briefs")}))
    before = files(tmp_path)
    assert "output directory overlaps coordination store" in compose(root, expect=2)["error"]
    assert files(tmp_path) == before and not (tmp_path / "briefs").exists()


FROZEN_COMPOSE = ("import datetime,runpy,sys\n"
                  "class Frozen(datetime.datetime):\n"
                  "    @classmethod\n"
                  "    def now(cls,tz=None): return cls(2026,11,7,12,tzinfo=tz)\n"
                  "datetime.datetime=Frozen\n"
                  "tool,root=sys.argv[1:]\n"
                  "sys.argv=[tool,'compose','--root',root,'--initiative','a','--endpoint','a/lane/f2']\n"
                  "runpy.run_path(tool,run_name='__main__')\n")


@secure_publication
@pytest.mark.parametrize("special", ["fifo", "directory"])
def test_special_destination_refuses_without_hanging_or_writing(pilot, special):  # noqa: F811
    root, _ = pilot
    code, first = faulted_cli(root, FROZEN_COMPOSE)
    assert code == 0
    path = Path(first["brief"]["path"])
    path.unlink()
    if special == "fifo":
        os.mkfifo(path)
    else:
        path.mkdir()
    before = files(root.parent)
    code, answer = faulted_cli(root, FROZEN_COMPOSE, timeout=2)
    assert code == 2 and answer["error"] == "brief must be a regular file"
    assert files(root.parent) == before
    assert stat.S_ISFIFO(path.stat().st_mode) if special == "fifo" else path.is_dir()


@secure_publication
def test_returned_path_must_identify_the_written_inode_after_an_ancestor_moves(pilot):  # noqa: F811
    root, _ = pilot
    base = root.parent
    moved = base.with_name(base.name + "-moved")
    driver = ("import os,runpy,sys\nfrom pathlib import Path\n"
              "tool,root=sys.argv[1:]\nbase=Path(root).parent\nreal_open=os.open\nmoved=False\n"
              "def opening(path,flags,*args,**kwargs):\n"
              "    global moved\n"
              "    if str(path).startswith('.fresh-') and flags & os.O_CREAT and not moved:\n"
              "        moved=True\n"
              "        base.rename(base.with_name(base.name+'-moved'))\n"
              "        base.mkdir()\n"
              "    return real_open(path,flags,*args,**kwargs)\n"
              "os.open=opening\n"
              "sys.argv=[tool,'compose','--root',root,'--initiative','a','--endpoint','a/lane/f2']\n"
              "runpy.run_path(tool,run_name='__main__')\n")
    code, answer = faulted_cli(root, driver)
    assert code == 3 and "published brief pathname no longer identifies written file" in answer["error"]
    assert list(base.iterdir()) == [] and list((moved / "briefs").iterdir()) == []


@secure_publication
def test_initiative_named_serve_composes_without_operational_import_side_effects(tmp_path):
    root = tmp_path / "mailbox"
    invoke(root, "init", {"schema": "aegis.hierarchy-pilot/v1", "endpoints": {"serve/front-door": {}, "serve/orchestrator": {}},
                          "counterparts": [], "writer_limit": 1})
    provision_record(root, initiative="serve")
    answer = cli("compose", "--root", root, "--initiative", "serve", "--endpoint", "serve/orchestrator")
    assert answer["ok"] is True and sections(answer["brief"])["Role contract"][0]["role"] == "orchestrator"


@secure_publication
@pytest.mark.parametrize("family", ["claude", "codex"])
@pytest.mark.parametrize("role", ["front-door", "orchestrator", "router", "decider", "implementer", "integrator", "reviewer"])
def test_template_rendering_exactly_matches_launcher_in_a_separate_process(tmp_path, role, family):
    endpoint = "a/lane/" + role if role in {"implementer", "integrator", "reviewer"} else "a/" + role
    root = tmp_path / "mailbox"
    invoke(root, "init", {"schema": "aegis.hierarchy-pilot/v1", "endpoints": {"a/front-door": {}, "a/orchestrator": {},
        endpoint: {"kind": role} if "/lane/" in endpoint else {}}, "counterparts": [], "writer_limit": 1})
    write_plan(SimpleNamespace(base=tmp_path), hierarchy="a", team="claude-code" if family == "claude" else "codex-cli", stand_ins={})
    answer = compose(root, endpoint)
    text = Path(answer["brief"]["path"]).read_text()
    inline = "\n".join(line[2:] for line in text.splitlines() if line.startswith("> "))
    driver = ("import json,sys\nfrom types import SimpleNamespace\n"
              "from pathlib import Path\nsource,root,endpoint,family=sys.argv[1:]\n"
              "sys.argv=[str(Path(source)/'tools/hierarchy_launcher.py')]\n"
              "sys.path.insert(0,str(Path(source)/'tools'))\n"
              "from hierarchy_launcher import start_prompt\nfrom hierarchy_mailbox import Mailbox\n"
              "prompt,contracts=start_prompt(SimpleNamespace(mailbox=Mailbox(root),setup={'source':source}),endpoint,family)\n"
              "print(json.dumps({'text':prompt.partition('\\n\\n')[2].rpartition('\\n\\n')[0],'contracts':contracts}))\n")
    proc = subprocess.run([sys.executable, "-I", "-B", "-c", driver, str(ROOT), str(root), endpoint, family],
                          capture_output=True, text=True, timeout=15)
    assert proc.returncode == 0 and not proc.stderr, proc.stdout + proc.stderr
    expected = json.loads(proc.stdout)
    assert inline == expected["text"]
    assert [row["ref"] for row in sections(answer["brief"])["Role contract"]] == expected["contracts"]


@lifecycle_only
def test_valid_large_settled_lifecycle_record_uses_the_lifecycle_reader_limit(pilot, tmp_path):  # noqa: F811
    root, _ = pilot
    ledger = Ledger(tmp_path)
    paths = [str(tmp_path / "declared" / str(index)) + "/" + "/".join(["p" * 100] * 22) for index in range(128)]
    value = request("large-history", paths=paths)
    receipt = ledger.publish(value)
    record = ledger.path / "events" / ("%06d.json" % receipt["sequence"])
    assert 262144 < len(record.read_bytes()) < 1048576
    ledger.event("disposition", status="FINAL", resolution={"kind": "next", "request": raw_request(request("pending")),
                 "evidence": ledger.evidence}, **ledger.target(value))
    before = files(tmp_path)
    answer = compose(root)
    assert answer["entries"] < 20
    after = files(tmp_path)
    after.pop(str(Path(answer["brief"]["path"]).relative_to(tmp_path)))
    assert after == before


@lifecycle_only
def test_expiry_decisions_are_reproducible_from_explicit_as_of(pilot, tmp_path):  # noqa: F811
    root, _ = pilot
    ledger = Ledger(tmp_path)
    ledger.publish(request("timed", continuation={"members": [], "max_starts": 1, "expires_at": "2026-11-07T12:00:00Z"}))
    before = compose(root, as_of="2026-11-07T11:59:59Z")
    after = compose(root, as_of="2026-11-07T12:00:01Z")
    assert any(row.get("request_id") == "timed" for row in sections(before["brief"])["Approved scope"])
    assert not any(row.get("request_id") == "timed" for row in sections(after["brief"])["Approved scope"])
    assert compose(root, as_of="2026-11-07T11:59:59Z") == before
    body = Path(before["brief"]["path"]).read_text()
    assert "2026-11-07T11:59:59" in body and "validate expiry live" in body


@pytest.mark.parametrize("value", ["yesterday", "2026-11-07T12:00:00-05:00"])
def test_as_of_requires_rfc3339_utc_without_writes(pilot, value):  # noqa: F811
    root, _ = pilot
    before = files(root.parent)
    assert "invalid --as-of" in compose(root, as_of=value, expect=2)["error"]
    assert files(root.parent) == before


@secure_publication
@pytest.mark.parametrize("order", ["compose-then-bind", "bind-then-compose"])
def test_successor_lifetime_reads_use_one_predecessor_aggregate(tmp_path, order):
    root, delivery, checkpoint = receipt_fixture(tmp_path, endpoint="a/root")
    for index in range(248):
        invoke(root, "publish", message(recipient="a/root", identifier="lifetime-%03d" % index))
    invoke(root, "publish", message(recipient="a/root", identifier="esc-7", kind="escalation"))
    cursor = None
    for _ in range(4):
        flags = {"after": cursor} if cursor else {}
        page = invoke(root, "inbox", endpoint="a/root", delivery_dir=delivery, mark_read=True,
                      host="host-one", session="a/root", generation=1, limit=100, **flags)
        cursor = page["next_after"]
        if cursor is None:
            break
    assert cursor is None
    binding = {"endpoint": "a/root", "host": "host-two", "session": "successor", "expected_generation": 1,
               "checkpoint": checkpoint}
    if order == "bind-then-compose":
        invoke(root, "bind", binding)
    answer = compose(root, "a/root")
    rows = sections(answer["brief"])["Unread work"]
    assert answer["entries"] < 20 and len(rows) == 1
    aggregate = rows[0]
    assert aggregate["state"] == "read_by_predecessor" and aggregate["count"] == 250
    assert aggregate["generation"] == 2 and aggregate["message_types"]["escalation"] == 1
    assert aggregate["ref"] == ref(aggregate["ref"]["path"])
    assert "esc-7" in json.loads(Path(aggregate["ref"]["path"]).read_text())["message_ids"]
    if order == "compose-then-bind":
        binding["checkpoint"]["briefs"].append(answer["brief"])
        invoke(root, "bind", binding)
    own = compose(root, "a/root", target_generation=1, expect=2)
    assert "target generation precedes current binding" in own["error"]


@secure_publication
def test_explicit_current_target_generation_applies_its_own_reads(tmp_path):
    root, delivery, _ = receipt_fixture(tmp_path, endpoint="a/root")
    invoke(root, "inbox", endpoint="a/root", delivery_dir=delivery, mark_read=True,
           host="host-one", session="a/root", generation=1)
    answer = compose(root, "a/root", target_generation=1)
    assert sections(answer["brief"])["Unread work"] == []
    assert "Target generation: 1" in Path(answer["brief"]["path"]).read_text()


@secure_publication
@pytest.mark.skipif(not hasattr(os, "O_PATH"), reason="search-only traversal uses Linux O_PATH")
def test_search_only_parent_directories_allow_publication(pilot):  # noqa: F811
    root, _ = pilot
    ancestor = root.parent / "search-only"
    base = ancestor / "run"
    base.mkdir(parents=True)
    root.rename(base / "mailbox")
    root = base / "mailbox"
    mode = stat.S_IMODE(ancestor.stat().st_mode)
    ancestor.chmod(0o111)
    try:
        answer = compose(root)
    finally:
        ancestor.chmod(mode)
    assert Mailbox(root).brief(answer["brief"])


@secure_publication
def test_directory_eacces_is_a_permission_refusal(pilot):  # noqa: F811
    root, _ = pilot
    driver = ("import errno,os,runpy,sys\n"
              "tool,root=sys.argv[1:]\nreal_open=os.open\n"
              "def opening(path,flags,*args,**kwargs):\n"
              "    if str(path)=='briefs': raise PermissionError(errno.EACCES,'fixture directory denied')\n"
              "    return real_open(path,flags,*args,**kwargs)\n"
              "os.open=opening\n"
              "sys.argv=[tool,'compose','--root',root,'--initiative','a','--endpoint','a/lane/f2']\n"
              "runpy.run_path(tool,run_name='__main__')\n")
    code, answer = faulted_cli(root, driver)
    assert code == 2 and "publication directory permission denied" in answer["error"]
    assert "changed" not in answer["error"]


def structured_job(tmp_path, changes=None, missing=None):
    root, _, _ = receipt_fixture(tmp_path)
    value = {"schema": "aegis.hierarchy-job-packet/v2", "recipe": "tests", "checkout": str(tmp_path),
             "commit": "a" * 40, "tree": "b" * 40, "recipes_sha256": "c" * 64,
             "after": {"message_id": "prior", "sha256": "d" * 64}, **(changes or {})}
    if value["schema"] == "aegis.hierarchy-job-packet/v1":
        value.pop("after", None)
        value.pop("recipes_sha256", None)
    if missing is not None:
        value.pop(missing)
    path = tmp_path / "structured-packet.md"
    path.write_text(json.dumps(value))
    invoke(root, "publish", message(recipient="a/root", identifier="structured-job", kind="job_request", brief=ref(path)))
    return root, path, value


@pytest.mark.parametrize("changes,missing,field", [
    ({}, "after", "after"),
    ({"commit": {"transcript": "DO_NOT_INLINE_PACKET_TRANSCRIPT"}}, None, "commit"),
    ({"schema": "aegis.hierarchy-job-packet/v99"}, None, "schema"),
    ({}, "recipes_sha256", "recipes_sha256"),
    ({}, "tree", "tree"),
    ({"checkout": {}}, None, "checkout"),
    ({"tree": []}, None, "tree"),
    ({"paths": [{"transcript": "DO_NOT_INLINE_PACKET_TRANSCRIPT"}]}, None, "paths"),
    ({"paths": "tests"}, None, "paths"),
    ({"paths": ["../escape.py"]}, None, "paths"),
    ({"dirty_content_sha256": {}}, None, "dirty_content_sha256"),
    ({"expected_tree": {}}, None, "expected_tree"),
    ({"merge": {}}, None, "merge"),
    ({"message": {}}, None, "message"),
    ({"recipe": {}}, None, "recipe"),
    ({"after": {"message_id": {}, "sha256": "d" * 64}}, None, "after"),
    ({"recipes_sha256": []}, None, "recipes_sha256"),
])
def test_malformed_structured_packets_refuse_before_extracting_fields(tmp_path, changes, missing, field):
    root, path, _ = structured_job(tmp_path, changes, missing)
    before = files(tmp_path)
    error = compose(root, "a/orchestrator", expect=2)["error"]
    assert str(path) in error and field in error
    assert "DO_NOT_INLINE_PACKET_TRANSCRIPT" not in error
    assert files(tmp_path) == before and not (tmp_path / "briefs").exists()


@pytest.mark.parametrize("changes,missing,field", [
    ({}, "after", "after"),
    ({"commit": {"transcript": "DO_NOT_INLINE_PACKET_TRANSCRIPT"}}, None, "commit"),
])
def test_packet_rejection_agrees_with_the_runners_admission_checks(tmp_path, changes, missing, field):
    root, path, _ = structured_job(tmp_path, changes, missing)
    # No standalone schema validator exists. The actual admission API must fail
    # on these fields before it could reach any checkout or execution boundary.
    driver = ("import json,sys\nfrom pathlib import Path\n"
              "source,root,packet,checkout=sys.argv[1:]\n"
              "sys.path.insert(0,str(Path(source)/'tools'))\n"
              "from hierarchy_jobs import admit\nfrom hierarchy_mailbox import Mailbox\n"
              "mailbox=Mailbox(root)\nmessage=mailbox.messages()['structured-job']['message']\n"
              "try:\n"
              "    admit(None,{'checkouts':[checkout]},message,mailbox,{'recipes':{'tests':{'kind':'command','steps':[]}}})\n"
              "except ValueError as error:\n    print(json.dumps({'error':str(error)}))\n"
              "else:\n    raise AssertionError('malformed packet reached admission')\n")
    result = subprocess.run([sys.executable, "-I", "-B", "-c", driver, str(ROOT), str(root), str(path), str(tmp_path)],
                            capture_output=True, text=True, timeout=15,
                            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert result.returncode == 0 and not result.stderr, result.stdout + result.stderr
    assert field in json.loads(result.stdout)["error"]
    assert field in compose(root, "a/orchestrator", expect=2)["error"]


@pytest.mark.parametrize("after", [None, []])
def test_non_object_dependency_names_the_after_field(tmp_path, after):
    root, path, _ = structured_job(tmp_path, {"after": after})
    before = files(tmp_path)
    error = compose(root, "a/orchestrator", expect=2)["error"]
    assert str(path) in error and ": invalid after:" in error
    assert files(tmp_path) == before


@secure_publication
@pytest.mark.parametrize("version", [1, 2])
def test_valid_packet_source_fields_remain_scalar_and_paths_are_strings(tmp_path, version):
    value = {"schema": "aegis.hierarchy-job-packet/v%d" % version,
             "paths": ["tests/example.py::test_one"], "dirty_content_sha256": hashlib.sha256(b"").hexdigest()}
    root, path, packet = structured_job(tmp_path, value)
    rows = sections(compose(root, "a/orchestrator")["brief"])
    source = next(row["source"] for row in rows["Source identity"] if row.get("job_id") == "structured-job")
    assert source["commit"] == packet["commit"] and source["tree"] == packet["tree"]
    assert source["paths"] == packet["paths"]
    assert all(isinstance(item, str) for item in source["paths"])


FSYNC_DRIVER = ("import errno,fcntl,json,os,runpy,stat,sys\nfrom pathlib import Path\n"
                "tool,root,fail,peer=sys.argv[1:]\nbase=Path(root).parent\ntrace=base/'fsync-trace.json'\n"
                "events=[]\nrenamed=False\nalready_published=any((base/'briefs').glob('fresh-*.md'))\n"
                "real_fsync,real_replace,real_mkdir=os.fsync,os.replace,os.mkdir\n"
                "def making(path,*args,**kwargs):\n"
                "    result=real_mkdir(path,*args,**kwargs)\n"
                "    if peer=='yes' and str(path)=='briefs':\n"
                "        events.append('peer_created')\n"
                "        raise FileExistsError(errno.EEXIST,'peer created the directory without syncing its parent')\n"
                "    return result\n"
                "def replacing(*args,**kwargs):\n"
                "    global renamed\n    result=real_replace(*args,**kwargs)\n    renamed=True\n    return result\n"
                "def syncing(fd):\n"
                "    metadata=os.fstat(fd)\n"
                "    if stat.S_ISDIR(metadata.st_mode):\n"
                "        assert renamed or already_published,'directory synced before rename'\n"
                "        flags=fcntl.fcntl(fd,fcntl.F_GETFL)\n"
                "        assert flags & os.O_ACCMODE == os.O_RDONLY\n"
                "        assert not flags & getattr(os,'O_PATH',0)\n"
                "        parent=base.stat()\n"
                "        kind='parent' if (metadata.st_dev,metadata.st_ino)==(parent.st_dev,parent.st_ino) else 'directory'\n"
                "    else:\n        assert stat.S_ISREG(metadata.st_mode)\n        kind='file'\n"
                "    events.append(kind)\n"
                "    if kind==fail: raise OSError('fixture '+kind+' fsync refused')\n"
                "    return real_fsync(fd)\n"
                "os.fsync,os.replace,os.mkdir=syncing,replacing,making\n"
                "sys.argv=[tool,'compose','--root',root,'--initiative','a','--endpoint','a/lane/f2','--as-of','2026-11-07T12:00:00Z']\n"
                "try:\n    runpy.run_path(tool,run_name='__main__')\n"
                "finally:\n    trace.write_text(json.dumps(events))\n")


def traced_publication(root, fail="", peer_creation=False):
    proc = subprocess.run([sys.executable, "-I", "-B", "-c", FSYNC_DRIVER, str(TOOL), str(root), fail,
                           "yes" if peer_creation else "no"],
                          capture_output=True, text=True, timeout=15,
                          env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert not proc.stderr, proc.stderr
    return proc.returncode, json.loads(proc.stdout), json.loads((root.parent / "fsync-trace.json").read_text())


@secure_publication
@pytest.mark.parametrize("existing", ["none", "directory", "brief"])
def test_publication_syncs_directory_and_parent_on_every_success(pilot, existing):  # noqa: F811
    root, _ = pilot
    if existing == "directory":
        (root.parent / "briefs").mkdir()
    elif existing == "brief":
        compose(root, as_of=AS_OF)
    code, answer, events = traced_publication(root)
    assert code == 0, answer
    expected = {"none": ["file", "directory", "parent"], "directory": ["file", "directory", "parent"],
                "brief": ["directory", "parent"]}
    assert events == expected[existing]
    assert Mailbox(root).brief(answer["brief"])


@secure_publication
@pytest.mark.parametrize("failed", ["directory", "parent"])
def test_directory_sync_failure_never_reports_publication_success(pilot, failed):  # noqa: F811
    root, _ = pilot
    code, answer, events = traced_publication(root, failed)
    assert code == 3 and "ok" not in answer
    assert answer["error"] == "brief publication failed: fixture " + failed + " fsync refused"
    assert events[-1] == failed


@secure_publication
def test_parent_sync_failure_is_not_forgotten_on_retry(pilot):  # noqa: F811
    root, _ = pilot
    code, _, events = traced_publication(root, "parent")
    assert code == 3 and events == ["file", "directory", "parent"]
    published = list((root.parent / "briefs").glob("fresh-*.md"))
    assert len(published) == 1
    reference = ref(published[0])
    contents = published[0].read_bytes()
    code, _, events = traced_publication(root, "parent")
    assert code == 3 and events == ["directory", "parent"]
    code, answer, events = traced_publication(root)
    assert code == 0 and events == ["directory", "parent"]
    assert answer["brief"] == reference and Mailbox(root).brief(reference) == contents


@secure_publication
def test_peer_creation_without_parent_sync_is_completed_by_this_composer(pilot):  # noqa: F811
    root, _ = pilot
    code, answer, events = traced_publication(root, peer_creation=True)
    assert code == 0, answer
    assert events == ["peer_created", "file", "directory", "parent"]
    assert Mailbox(root).brief(answer["brief"])


@secure_publication
@pytest.mark.skipif(not hasattr(os, "O_PATH"), reason="search-only traversal uses Linux O_PATH")
def test_unreadable_output_parent_cannot_report_durable_success(pilot):  # noqa: F811
    root, _ = pilot
    compose(root, as_of=AS_OF)
    base = root.parent
    mode = stat.S_IMODE(base.stat().st_mode)
    base.chmod(0o111)
    try:
        error = compose(root, as_of=AS_OF, expect=3)["error"]
    finally:
        base.chmod(mode)
    assert "brief publication failed" in error and "Permission denied" in error


@secure_publication
@pytest.mark.parametrize("paths", [None, "", 0, False, {}, []])
def test_no_paths_packets_match_the_runners_falsy_path_handling(tmp_path, paths):
    root, path, _ = structured_job(tmp_path, {"paths": paths})
    driver = ("import json,sys\nfrom pathlib import Path\nsource,packet,checkout=sys.argv[1:]\n"
              "sys.path.insert(0,str(Path(source)/'tools'))\nfrom hierarchy_jobs import checked_paths\n"
              "print(json.dumps(checked_paths(json.loads(Path(packet).read_text()),"
              "{'kind':'command','steps':[['$python','-c','pass']]},checkout)))\n")
    result = subprocess.run([sys.executable, "-I", "-B", "-c", driver, str(ROOT), str(path), str(tmp_path)],
                            capture_output=True, text=True, timeout=15,
                            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert result.returncode == 0 and not result.stderr, result.stdout + result.stderr
    expected = json.loads(result.stdout)
    assert expected == []
    before = files(tmp_path)
    answer = compose(root, "a/orchestrator")
    source = next(row["source"] for row in sections(answer["brief"])["Source identity"] if row.get("job_id") == "structured-job")
    assert source["paths"] == expected
    after = files(tmp_path)
    after.pop(str(Path(answer["brief"]["path"]).relative_to(tmp_path)))
    assert after == before


@secure_publication
def test_valid_merge_packet_composes_without_admitting_or_executing_it(tmp_path):
    root, path, packet = structured_job(tmp_path, {"schema": "aegis.hierarchy-job-packet/v1", "recipe": "merge",
        "merge": "c" * 40, "expected_tree": "d" * 40, "message": "Merge reviewed candidate"})
    before = files(tmp_path)
    answer = compose(root, "a/orchestrator")
    row = next(row for row in sections(answer["brief"])["Source identity"] if row.get("job_id") == "structured-job")
    assert row["ref"] == ref(path)
    assert row["source"]["merge"] == packet["merge"] and row["source"]["expected_tree"] == packet["expected_tree"]
    assert "paths" not in row["source"]
    after = files(tmp_path)
    after.pop(str(Path(answer["brief"]["path"]).relative_to(tmp_path)))
    assert after == before
