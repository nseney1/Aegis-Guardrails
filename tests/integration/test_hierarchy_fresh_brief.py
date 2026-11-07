"""Fresh-thread briefs through the CLI; records remain inert claims."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from tests.integration.test_hierarchy_mailbox import ROOT, invoke, message, pilot, receipt_fixture  # noqa: F401
from tests.integration.test_hierarchy_handoff import handoff
from tests.integration.test_hierarchy_host_plan import write_plan
from tests.integration.test_hierarchy_lifecycle import Ledger, SOURCE, raw_request, request
from tests.integration.test_hierarchy_small_change_admission import SmallChange
from tools.hierarchy_mailbox import Mailbox


TOOL = ROOT / "tools" / "hierarchy_fresh_brief.py"
SECTIONS = ("Role contract", "Approved scope", "Source identity", "Open obligations",
            "Dependencies", "Unread work", "Evidence references")
ENDPOINT = "a/lane/f2"


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


def test_unknown_effects_and_woken_unread_are_never_dropped(records):
    root, _, _, wake = records
    rows = sections(compose(root)["brief"])
    assert any(row.get("request_id") == "uncertain" and row.get("state") == "unknown_effect"
               for row in rows["Open obligations"])
    assert any(row.get("message_id") == "woken-note" and row.get("state") == "woken"
               for row in rows["Unread work"])
    assert ref(wake) in [row["ref"] for row in rows["Evidence references"]]


def test_determinism_and_no_store_mutations(records):
    root, _, _, _ = records
    before = files(root.parent)
    first = compose(root)
    raw = Path(first["brief"]["path"]).read_bytes()
    after = files(root.parent)
    assert after.pop(str(Path(first["brief"]["path"]).relative_to(root.parent))) == raw
    assert after == before
    assert compose(root) == first
    assert Path(first["brief"]["path"]).read_bytes() == raw


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


def test_corruption_refuses_verify_and_mailbox_read(pilot):  # noqa: F811
    root, _ = pilot
    brief = compose(root)["brief"]
    Path(brief["path"]).write_bytes(b"corrupted\n")
    assert cli("verify", "--path", brief["path"], "--sha256", brief["sha256"], expect=2)["error"] == "brief sha256 mismatch"
    with pytest.raises(ValueError, match="^brief sha256 mismatch$"):
        Mailbox(root).brief(brief, verify=True)


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
    ({"lifecycle": "/missing-fresh-brief-lifecycle"}, "lifecycle directory unavailable"),
])
def test_invalid_inputs_refuse_without_writing(pilot, flags, error):  # noqa: F811
    root, _ = pilot
    before = files(root.parent)
    assert error in compose(root, expect=2, **flags)["error"]
    assert files(root.parent) == before


def test_verify_detects_changed_reference_even_with_unchanged_brief(pilot):  # noqa: F811
    root, _ = pilot
    brief = compose(root)["brief"]
    manifest = root / "manifest.json"
    manifest.write_bytes(manifest.read_bytes() + b"\n")
    assert "reference sha256 mismatch" in cli("verify", "--path", brief["path"], "--sha256", brief["sha256"], expect=2)["error"]


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


def test_recorded_reads_are_excluded_but_no_delivery_history_is_conservative(tmp_path):
    root, delivery, _ = receipt_fixture(tmp_path, endpoint="a/root")
    invoke(root, "inbox", endpoint="a/root", delivery_dir=delivery, mark_read=True,
           host="host-one", session="a/root", generation=1)
    brief = compose(root, "a/root")["brief"]
    assert sections(brief)["Unread work"] == []
    assert "receipt-note" not in json.dumps(sections(brief)["Unread work"])
    assert any(row.get("kind") == "delivery_read" for row in sections(brief)["Evidence references"])


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
    assert compose(root, "a/orchestrator", expect=2)["error"] == "job packet is not valid JSON"
    assert files(tmp_path) == before


def test_failed_atomic_publication_leaves_no_brief_or_temporary_file(pilot):  # noqa: F811
    root, _ = pilot
    # Inject only at the OS boundary, then enter the actual CLI. No composer internals are replaced.
    driver = ("import os,runpy,sys\n"
              "def refuse(*args):\n    raise OSError('fixture replace refused')\n"
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
