"""Handoff verifies launcher stop evidence before processing any endpoint in a spec."""
import hashlib
import json
import os
import shlex
import signal
import uuid

import pytest

from tests.integration.test_hierarchy_handoff import handoff, mailbox_files
from tests.integration.test_hierarchy_launcher import REVIEW, census, hold, launch, wait_until  # noqa: F401
from tests.integration.test_hierarchy_mailbox import invoke


pytestmark = pytest.mark.skipif(os.name == "nt", reason="launcher process matching is POSIX only")


def spec_for(launch, endpoints=(REVIEW,), **changes):
    brief = launch.base / "handoff-brief.md"
    brief.write_bytes(b"Continue the approved scope.\n")
    reference = {"path": str(brief), "sha256": hashlib.sha256(brief.read_bytes()).hexdigest()}
    return {"schema": "aegis.hierarchy-handoff/v1", "host": "codex-cli", "session": "successor",
            "outgoing_stopped": True,
            "entries": [{"root": str(launch.root), "endpoint": endpoint, "briefs": [reference]}
                        for endpoint in endpoints], **changes}


def record_paths(launch, endpoint=REVIEW):
    return sorted((launch.base / "launches" / endpoint.replace("/", "%2F")).glob("*.json"))


def change_record(path, **changes):
    record = json.loads(path.read_text(encoding="utf-8"))
    path.write_text(json.dumps({**record, **changes}) + "\n", encoding="utf-8")


def refused_unchanged(launch, spec, reason, endpoint=REVIEW):
    before = mailbox_files(launch.base)
    result = handoff(launch.tmp, spec, 2)
    assert mailbox_files(launch.base) == before
    assert endpoint in result["error"] and reason in result["error"]
    command = shlex.join(["hierarchy_launcher.py", "--base", str(launch.base), "stop", "--endpoint", endpoint])
    assert command in result["error"]
    return result


def held_session(launch, session):
    process = hold(launch, session, 'exec codex exec --json hold "$0"', session, start_new_session=True)
    try:
        wait_until(lambda: process.pid in census(session))
    except BaseException:
        finish(process)
        raise
    return process


def finish(process):
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGKILL)
    process.wait(timeout=5)


def stopped(launch):
    session = launch.start(cwd=str(launch.source))["session"]
    process = held_session(launch, session)
    try:
        result = launch.run("stop", "--endpoint", REVIEW, "--grace-seconds", "1")
        assert result["state"] == "stopped"
        process.wait(timeout=5)
    finally:
        finish(process)
    return session


def test_a_launcher_start_without_a_stop_refuses_without_writes(launch):  # noqa: F811
    launch.start(cwd=str(launch.source))
    refused_unchanged(launch, spec_for(launch), "stop record")


def test_stop_failed_is_not_stop_evidence(launch):  # noqa: F811
    stopped(launch)
    change_record(record_paths(launch)[-1], state="stop_failed")
    refused_unchanged(launch, spec_for(launch), "stop_failed")


def test_a_stopped_record_with_a_live_session_process_is_refused(launch):  # noqa: F811
    session = stopped(launch)
    process = held_session(launch, session)
    try:
        refused_unchanged(launch, spec_for(launch), "live process")
        assert process.poll() is None
    finally:
        finish(process)


def test_a_held_wake_marker_refuses_before_any_entry(launch):  # noqa: F811
    launch.add_role("pilot/front-door", host="codex-cli", session=str(uuid.uuid4()), cwd=str(launch.source))
    stopped(launch)
    marker = launch.root / ".wake-pilot%2Flane%2Freview.lock"
    marker.write_text("{}", encoding="utf-8")
    refused_unchanged(launch, spec_for(launch, ("pilot/front-door", REVIEW)), "wake marker")
    assert marker.read_text(encoding="utf-8") == "{}"


@pytest.mark.parametrize("state", ["stopped", "not_running"])
def test_stop_evidence_binds_and_records_exact_record_hashes(launch, state):  # noqa: F811
    if state == "stopped":
        stopped(launch)
    else:
        launch.start(cwd=str(launch.source))
        assert launch.run("stop", "--endpoint", REVIEW)["state"] == state
    launch_path, status_path = record_paths(launch)
    result = handoff(launch.tmp, spec_for(launch), 0)
    [entry] = result["entries"]
    assert entry["ok"] is True and entry["generation"] == 2
    assert entry["stop_evidence"] == {
        "launch": str(launch_path), "launch_sha256": hashlib.sha256(launch_path.read_bytes()).hexdigest(),
        "status": str(status_path), "status_sha256": hashlib.sha256(status_path.read_bytes()).hexdigest(),
        "state": state}
    binding = launch.binding()
    assert binding["session"] == "successor" and binding["generation"] == 2 and binding["ready"] is False
    invoke(launch.root, "ack-handoff", entry["acknowledge"])
    assert launch.binding()["ready"] is True


def test_a_non_launcher_session_still_requires_the_caller_assertion(launch):  # noqa: F811
    launch.add_role(REVIEW, host="codex-cli", session=str(uuid.uuid4()), cwd=str(launch.source))
    spec = spec_for(launch, outgoing_stopped=False)
    before = mailbox_files(launch.base)
    result = handoff(launch.tmp, spec, 2)
    assert result == {"error": "outgoing session must be stopped before replacement"}
    assert mailbox_files(launch.base) == before
    result = handoff(launch.tmp, spec_for(launch), 0)
    assert result["entries"][0]["stop_evidence"] == "caller_asserted"
    assert launch.binding()["generation"] == 2


def test_one_bad_launcher_entry_refuses_the_whole_spec(launch):  # noqa: F811
    stopped(launch)
    other = "pilot/front-door"
    launch.start(endpoint=other, cwd=str(launch.source))
    refused_unchanged(launch, spec_for(launch, (REVIEW, other)), "stop record", endpoint=other)
    assert launch.binding()["generation"] == launch.binding(other)["generation"] == 1


def test_an_extra_entry_field_does_not_bypass_the_batch_stop_check(launch):  # noqa: F811
    launch.add_role("pilot/front-door", host="codex-cli", session=str(uuid.uuid4()), cwd=str(launch.source))
    launch.start(cwd=str(launch.source))
    spec = spec_for(launch, ("pilot/front-door", REVIEW))
    spec["entries"][1]["extra"] = True
    refused_unchanged(launch, spec, "stop record")


@pytest.mark.parametrize("change", [{"session": "another-session"}, {"generation": 2},
                                  {"endpoint": "pilot/front-door"}])
def test_a_stop_for_another_binding_is_not_evidence(launch, change):  # noqa: F811
    stopped(launch)
    change_record(record_paths(launch)[-1], **change)
    refused_unchanged(launch, spec_for(launch), "stop record")


def test_a_stop_timestamp_before_the_launch_is_not_evidence(launch):  # noqa: F811
    stopped(launch)
    change_record(record_paths(launch)[-1], at="2000-01-01T00:00:00.000000Z")
    refused_unchanged(launch, spec_for(launch), "after")


@pytest.mark.parametrize("action,state", [("stop", "stop_failed"), ("resume", "resumed")])
def test_a_later_failed_stop_or_resume_invalidates_an_earlier_stop(launch, action, state):  # noqa: F811
    stopped(launch)
    status = record_paths(launch)[-1]
    later = status.with_name("99991231T235959000000Z-later.json")
    later.write_bytes(status.read_bytes())
    change_record(later, action=action, state=state, at="9999-12-31T23:59:59.000000Z")
    refused_unchanged(launch, spec_for(launch), state)


def test_a_later_launch_requires_its_own_stop(launch):  # noqa: F811
    stopped(launch)
    start = record_paths(launch)[0]
    later = start.with_name("99991231T235959000000Z-later.json")
    later.write_bytes(start.read_bytes())
    change_record(later, at="9999-12-31T23:59:59.000000Z")
    refused_unchanged(launch, spec_for(launch), "stop record")


def test_a_failed_census_refuses_with_stop_guidance_and_no_writes(launch, monkeypatch):  # noqa: F811
    stopped(launch)
    ps = launch.bin / "ps"
    ps.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    ps.chmod(0o700)
    monkeypatch.setenv("PATH", str(launch.bin) + os.pathsep + os.environ["PATH"])
    refused_unchanged(launch, spec_for(launch), "process census failed")


def test_a_rerun_does_not_treat_the_successor_as_a_writer_to_replace(launch):  # noqa: F811
    stopped(launch)
    spec = spec_for(launch)
    handoff(launch.tmp, spec, 0)
    before = mailbox_files(launch.base)
    result = handoff(launch.tmp, spec, 0)
    assert result["entries"][0]["already_bound"] is True
    assert mailbox_files(launch.base) == before
