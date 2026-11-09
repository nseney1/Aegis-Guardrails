"""Handoff verifies launcher stop evidence before processing any endpoint in a spec."""
import hashlib
import importlib.util
import json
import os
import shlex
import signal
import subprocess
import sys
import uuid

import pytest

from tests.integration.test_hierarchy_handoff import HANDOFF, handoff, mailbox_files
from tests.integration.test_hierarchy_launcher import (  # noqa: F401
    Launch, REVIEW, LINUX_HOST_PROGRAMS, R2Facade, R2Processes, launch, wait_until,
)
from tests.integration.test_hierarchy_mailbox import invoke


pytestmark = [pytest.mark.skipif(os.name == "nt", reason="launcher process matching is POSIX only"),
              LINUX_HOST_PROGRAMS]


@pytest.fixture(autouse=True)
def modelled_processes(launch, monkeypatch, capsys):
    """Only complete logical argv is MODELLED; real READY/birth/UID/raw custody owns every test child."""
    from tests.integration.test_hierarchy_launcher_stop_ownership import R2Case

    case = R2Case(launch)
    cases, constructor = [case], Launch
    factory = handoff_module

    def scoped_launch(*args, **kwargs):
        # A second explicit checkout has separate receipts/custody, never a Python/native fallback.
        built = constructor(*args, **kwargs)
        cases.append(R2Case(built))
        return built

    def scoped_module(ps_fallback=False):
        control = factory()
        control.hierarchy_launcher = case.module(pidfds=False)
        if ps_fallback:
            # MODELLED loss of the /proc argv provider at its census boundary. Boot evidence remains physical.
            reader = control.hierarchy_launcher
            reader.process_census = lambda _session: reader.ProcessCensus(reader.ps_census(), "unproven")

            def ps(command, **options):
                environment = {**case.env, "PATH": os.environ.get("PATH", "")}
                return subprocess.run(command, **{**options, "env": environment, "stdin": subprocess.DEVNULL})
            control.hierarchy_launcher.subprocess = R2Facade(subprocess, run=ps)
        return control

    def scoped_handoff(tmp_path, spec, expected, ps_fallback=False):
        path = tmp_path / "handoff-spec.json"
        path.write_text(json.dumps(spec), encoding="utf-8")
        code = scoped_module(ps_fallback).main(["--spec", str(path)])
        captured = capsys.readouterr()
        assert not captured.err, captured.err
        assert code == expected, captured.out
        return json.loads(captured.out)

    monkeypatch.setattr(sys.modules[__name__], "handoff_module", scoped_module)
    monkeypatch.setattr(sys.modules[__name__], "handoff", scoped_handoff)
    monkeypatch.setattr(sys.modules[__name__], "Launch", scoped_launch)
    try:
        yield case
    finally:
        errors = []
        for owned in reversed(cases):
            try:
                owned.close()
            except BaseException as exc:
                errors.append(exc)
        if errors:
            raise RuntimeError("handoff fixture custody cleanup: " + "; ".join(str(exc) for exc in errors)) from errors[0]


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


def refused_unchanged(launch, spec, reason, endpoint=REVIEW, ps_fallback=False):
    before = mailbox_files(launch.base)
    result = handoff(launch.tmp, spec, 2, ps_fallback=ps_fallback)
    assert mailbox_files(launch.base) == before
    assert endpoint in result["error"] and reason in result["error"]
    assert stop_command(launch, endpoint) in result["error"]
    return result


def stop_command(launch, endpoint=REVIEW):
    return shlex.join(["hierarchy_launcher.py", "--base", str(launch.base), "stop", "--endpoint", endpoint])


def handoff_module():
    definition = importlib.util.spec_from_file_location("hierarchy_handoff_under_test", HANDOFF)
    module = importlib.util.module_from_spec(definition)
    definition.loader.exec_module(module)
    return module


def run_main(module, launch, spec, capsys, expected):
    path = launch.tmp / "handoff-spec.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    code = module.main(["--spec", str(path)])
    captured = capsys.readouterr()
    assert not captured.err, captured.err
    assert code == expected, captured.out
    return json.loads(captured.out)


def added_session(launch, generation, session=None):
    session = session or str(uuid.uuid4())
    if generation == 2:
        launch.add_role(REVIEW, host="codex-cli", session=str(uuid.uuid4()), cwd=str(launch.source))
        result = handoff(launch.tmp, spec_for(launch, session=session), 0)
        invoke(launch.root, "ack-handoff", result["entries"][0]["acknowledge"])
    result = launch.add_role(REVIEW, host="codex-cli", session=session, cwd=str(launch.source))
    assert result["generation"] == generation
    return session


def assert_evidence(entry, status, activity=None):
    assert entry["stop_evidence"] == {
        "launch": str(activity) if activity else None,
        "launch_sha256": hashlib.sha256(activity.read_bytes()).hexdigest() if activity else None,
        "status": str(status), "status_sha256": hashlib.sha256(status.read_bytes()).hexdigest(),
        "state": json.loads(status.read_text(encoding="utf-8"))["state"]}


def held_session(launch, session):
    case = launch.stop_case
    host = launch.binding()["host"]
    argv = ["claude", "--resume", session] if host == "claude-code" else ["codex", "exec", "resume", session]
    process = case.spawn(argv)
    process.stop_custody = case
    module = case.module(pidfds=False)
    try:
        wait_until(lambda: process.pid in {pid for pid, _ in module.session_processes(session, set(), host)})
    except BaseException:
        finish(process)
        raise
    return process


def finish(process):
    if process.poll() is None:
        custody = process.stop_custody.custody
        slot = next(slot for slot, entry in custody.entries.items() if entry["pid"] == process.pid)
        custody.kill_owned(slot)
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
    result = refused_unchanged(launch, spec_for(launch, ("pilot/front-door", REVIEW)), "wake marker")
    assert result["error"] == (
        "stop evidence for %s: wake marker is held: %s; inspect %s; once %s reports not_running, "
        "remove the marker and retry" % (REVIEW, marker, marker, stop_command(launch)))
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


def test_a_failed_census_explains_that_stop_cannot_fix_it(launch, monkeypatch):  # noqa: F811
    stopped(launch)
    ps = launch.bin / "ps"
    ps.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    ps.chmod(0o700)
    monkeypatch.setenv("PATH", str(launch.bin) + os.pathsep + os.environ["PATH"])
    result = refused_unchanged(launch, spec_for(launch), "process census failed", ps_fallback=True)
    assert result["error"] == (
        "stop evidence for %s: process census failed; error: process census failed; "
        "%s cannot fix it; repair the process census and retry" % (REVIEW, stop_command(launch)))


def test_a_missing_ps_explains_the_census_error_and_recovery(launch, monkeypatch):  # noqa: F811
    stopped(launch)
    monkeypatch.setenv("PATH", str(launch.bin))
    result = refused_unchanged(launch, spec_for(launch), "process census failed", ps_fallback=True)
    assert result["error"] == (
        "stop evidence for %s: process census failed; error: [Errno 2] No such file or directory: 'ps'; "
        "%s cannot fix it; repair the process census and retry" % (REVIEW, stop_command(launch)))


def test_a_census_timeout_preserves_the_error_and_changes_nothing(launch, monkeypatch, capsys):  # noqa: F811
    stopped(launch)
    spec = spec_for(launch)
    before = mailbox_files(launch.base)
    module = handoff_module(ps_fallback=True)
    run = module.hierarchy_launcher.subprocess.run

    def timeout(argv, **options):
        if argv[0] == "ps":
            raise subprocess.TimeoutExpired(argv, 10)
        return run(argv, **options)

    with monkeypatch.context() as patch:
        patch.setattr(module.hierarchy_launcher.subprocess, "run", timeout)
        result = run_main(module, launch, spec, capsys, 2)
    assert result["error"] == (
        "stop evidence for %s: process census failed; error: "
        "Command '['ps', '-ax', '-ww', '-o', 'pid=,pgid=,ppid=,ruid=,uid=,stat=,lstart=,args=']' timed out after 10 seconds; "
        "%s cannot fix it; repair the process census and retry" % (REVIEW, stop_command(launch)))
    assert mailbox_files(launch.base) == before


def test_a_rerun_does_not_treat_the_successor_as_a_writer_to_replace(launch):  # noqa: F811
    stopped(launch)
    spec = spec_for(launch)
    handoff(launch.tmp, spec, 0)
    before = mailbox_files(launch.base)
    result = handoff(launch.tmp, spec, 0)
    assert result["entries"][0]["already_bound"] is True
    assert result["entries"][0]["stop_evidence"] is None
    assert mailbox_files(launch.base) == before


@pytest.mark.parametrize("generation", [1, 2])
def test_an_added_session_with_stop_failed_is_launcher_managed(launch, generation):  # noqa: F811
    added_session(launch, generation)
    launch.run("stop", "--endpoint", REVIEW)
    change_record(record_paths(launch)[-1], state="stop_failed")
    refused_unchanged(launch, spec_for(launch), "stop_failed")


def test_a_generation_two_resume_after_a_stop_requires_another_stop(launch):  # noqa: F811
    added_session(launch, 2)
    launch.run("stop", "--endpoint", REVIEW)
    assert launch.run("resume", "--endpoint", REVIEW)["state"] == "resumed"
    refused_unchanged(launch, spec_for(launch), "resumed")


def test_a_generation_two_stop_after_a_resume_records_launcher_evidence(launch):  # noqa: F811
    session = added_session(launch, 2)
    launch.run("stop", "--endpoint", REVIEW)
    change_record(record_paths(launch)[-1], state="stop_failed")
    launch.run("resume", "--endpoint", REVIEW)
    activity = record_paths(launch)[-1]
    process = held_session(launch, session)
    try:
        assert launch.run("stop", "--endpoint", REVIEW)["state"] == "stopped"
        process.wait(timeout=5)
    finally:
        finish(process)
    status = record_paths(launch)[-1]
    result = handoff(launch.tmp, spec_for(launch), 0)
    assert result["entries"][0]["generation"] == 3
    assert_evidence(result["entries"][0], status, activity)


def test_a_stop_only_history_records_evidence_without_inventing_a_launch(launch):  # noqa: F811
    session = added_session(launch, 2)
    launch.run("stop", "--endpoint", REVIEW)
    change_record(record_paths(launch)[-1], state="stop_failed")
    process = held_session(launch, session)
    try:
        assert launch.run("stop", "--endpoint", REVIEW)["state"] == "stopped"
        process.wait(timeout=5)
    finally:
        finish(process)
    status = record_paths(launch)[-1]
    result = handoff(launch.tmp, spec_for(launch), 0)
    assert result["entries"][0]["generation"] == 3
    assert_evidence(result["entries"][0], status)


@pytest.mark.parametrize("generation", [1, 2])
@pytest.mark.parametrize("state", ["bind_busy", "bind_refused", "start_incomplete"])
def test_a_generationless_record_only_manages_generation_one(launch, generation, state):  # noqa: F811
    session = str(uuid.uuid4())
    result = launch.start(expect=3, mode="fail-after-thread", thread=session, cwd=str(launch.source))
    assert result["state"] == "start_incomplete" and result["generation"] is None
    [activity] = record_paths(launch)
    change_record(activity, state=state)
    added_session(launch, generation, session)
    if generation == 1:
        refused_unchanged(launch, spec_for(launch), "stop record")
        launch.run("stop", "--endpoint", REVIEW)
        result = handoff(launch.tmp, spec_for(launch), 0)
        assert_evidence(result["entries"][0], record_paths(launch)[-1], activity)
    else:
        result = handoff(launch.tmp, spec_for(launch), 0)
        assert result["entries"][0]["stop_evidence"] == "caller_asserted"


@pytest.mark.parametrize("endpoint,host", [("pilot/root", "codex-cli"), (REVIEW, "codex")])
def test_a_refused_stop_alone_does_not_manage_an_owner_or_native_session(launch, endpoint, host):  # noqa: F811
    launch.add_role(endpoint, host=host, session=str(uuid.uuid4()), cwd=str(launch.source))
    assert launch.run("stop", "--endpoint", endpoint, expect=2)["state"] == "refused"
    result = handoff(launch.tmp, spec_for(launch, (endpoint,)), 0)
    assert result["entries"][0]["stop_evidence"] == "caller_asserted"


def test_a_refused_resume_does_not_invalidate_a_valid_stop(launch):  # noqa: F811
    stopped(launch)
    activity, status = record_paths(launch)
    refused = launch.run("resume", "--endpoint", REVIEW)
    assert refused["state"] == "resumed"
    change_record(record_paths(launch)[-1], state="refused")
    result = handoff(launch.tmp, spec_for(launch), 0)
    assert_evidence(result["entries"][0], status, activity)


def test_a_stop_must_be_recorded_after_the_latest_resume(launch):  # noqa: F811
    added_session(launch, 2)
    launch.run("resume", "--endpoint", REVIEW)
    activity = json.loads(record_paths(launch)[-1].read_text(encoding="utf-8"))
    launch.run("stop", "--endpoint", REVIEW)
    change_record(record_paths(launch)[-1], at=activity["at"])
    refused_unchanged(launch, spec_for(launch), "after")


def test_a_wake_after_preflight_refuses_only_its_entry_and_a_rerun_finishes(launch, monkeypatch, capsys):  # noqa: F811
    stopped(launch)
    other_tmp = launch.tmp / "second"
    other_tmp.mkdir()
    other = Launch(other_tmp)
    other.init()
    stopped(other)
    spec = spec_for(launch)
    spec["entries"] += spec_for(other)["entries"]
    bindings_before = mailbox_files(other.root / "bindings")
    marker = other.root / ".wake-pilot%2Flane%2Freview.lock"
    module = handoff_module()
    check = module.stop_evidence
    injected = []

    def wake_at_recheck(mailbox, current):
        if mailbox.root == other.root and (mailbox.root / ".write.lock").exists():
            assert not injected
            marker.write_text("{}", encoding="utf-8")
            injected.append(True)
        return check(mailbox, current)

    with monkeypatch.context() as patch:
        patch.setattr(module, "stop_evidence", wake_at_recheck)
        result = run_main(module, launch, spec, capsys, 3)
    assert injected == [True]
    first, second = result["entries"]
    assert first["ok"] is True and first["generation"] == 2
    assert second["ok"] is False
    assert second["error"].startswith("stop evidence changed during handoff: stop evidence for %s: " % REVIEW)
    assert "wake marker is held: " + str(marker) in second["error"]
    assert mailbox_files(other.root / "bindings") == bindings_before
    assert other.binding()["generation"] == 1
    first_bindings = mailbox_files(launch.root / "bindings")
    assert other.run("stop", "--endpoint", REVIEW)["state"] == "not_running"
    marker.unlink()
    result = handoff(launch.tmp, spec, 0)
    first, second = result["entries"]
    assert first["already_bound"] is True and first["stop_evidence"] is None
    assert second["ok"] is True and second["generation"] == 2
    assert mailbox_files(launch.root / "bindings") == first_bindings
    assert other.binding()["session"] == spec["session"]


def background_session(launch, resumed=True):
    role = launch.add_role(REVIEW, host="claude-code", session=str(uuid.uuid4()),
                           cwd=str(launch.source), background=True)
    profile = json.loads((launch.base / "profiles" / "pilot%2Flane%2Freview-g1.wake.json").read_text(encoding="utf-8"))
    assert profile["mode"] == "background"
    if resumed:
        assert launch.run("resume", "--endpoint", REVIEW)["state"] == "resumed"
    return role["session"]


@pytest.mark.parametrize("resumed", [False, True])
def test_a_background_session_keeps_the_caller_assertion_after_resume(launch, resumed):  # noqa: F811
    background_session(launch, resumed)
    result = handoff(launch.tmp, spec_for(launch), 0)
    assert result["entries"][0]["stop_evidence"] == "caller_asserted"
    assert launch.binding()["generation"] == 2


def test_a_background_session_still_requires_outgoing_stopped(launch):  # noqa: F811
    background_session(launch)
    spec = spec_for(launch, outgoing_stopped=False)
    before = mailbox_files(launch.base)
    result = handoff(launch.tmp, spec, 2)
    assert result == {"error": "outgoing session must be stopped before replacement"}
    assert mailbox_files(launch.base) == before


@pytest.mark.parametrize("resumed", [False, True])
@pytest.mark.parametrize("blocker", ["wake marker", "live process"])
def test_a_background_writer_blocks_the_whole_batch(launch, resumed, blocker):  # noqa: F811
    session = background_session(launch, resumed)
    other_tmp = launch.tmp / "first-entry"
    other_tmp.mkdir()
    other = Launch(other_tmp)
    other.init()
    other.add_role(REVIEW, host="codex-cli", session=str(uuid.uuid4()), cwd=str(other.source))
    spec = spec_for(other)
    spec["entries"] += spec_for(launch)["entries"]
    other_before = mailbox_files(other.base)
    process = held_session(launch, session) if blocker == "live process" else None
    marker = launch.root / ".wake-pilot%2Flane%2Freview.lock"
    if blocker == "wake marker":
        marker.write_text("{}", encoding="utf-8")
    try:
        result = refused_unchanged(launch, spec, blocker)
        assert mailbox_files(other.base) == other_before
        assert "%s refuses background sessions" % stop_command(launch) in result["error"]
        if process is not None:
            assert process.poll() is None
        else:
            assert "inspect " + str(marker) in result["error"]
            assert "remove the marker and retry" in result["error"]
    finally:
        if process is not None:
            finish(process)


def test_a_background_session_still_requires_a_successful_census(launch, monkeypatch):  # noqa: F811
    background_session(launch)
    ps = launch.bin / "ps"
    ps.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    ps.chmod(0o700)
    monkeypatch.setenv("PATH", str(launch.bin) + os.pathsep + os.environ["PATH"])
    result = refused_unchanged(launch, spec_for(launch), "process census failed", ps_fallback=True)
    assert result["error"] == (
        "stop evidence for %s: process census failed; error: process census failed; "
        "%s cannot fix it; repair the process census and retry" % (REVIEW, stop_command(launch)))


def test_only_the_current_generations_background_mode_applies(launch):  # noqa: F811
    added_session(launch, 2)
    change_record(launch.base / "profiles" / "pilot%2Flane%2Freview-g1.wake.json", mode="background")
    launch.run("resume", "--endpoint", REVIEW)
    refused_unchanged(launch, spec_for(launch), "resumed")


def test_a_mailbox_association_error_gives_setup_guidance(launch):  # noqa: F811
    stopped(launch)
    other = launch.base / "other-mailbox"
    other.mkdir()
    (other / "manifest.json").write_bytes((launch.root / "manifest.json").read_bytes())
    provision = launch.base / "provision.json"
    change_record(provision, mailbox_root=str(other))
    result = refused_unchanged(launch, spec_for(launch), "launch records do not cover this mailbox")
    assert result["error"] == (
        "stop evidence for %s: launch records do not cover this mailbox; inspect %s mailbox_root and %s; "
        "%s will not change this setup; correct the mailbox association and retry"
        % (REVIEW, provision, launch.root, stop_command(launch)))


@pytest.mark.parametrize("raw,error", [
    ("{}", ""), ("[]", ""),
    ("{", "; error: Expecting property name enclosed in double quotes: line 1 column 2 (char 1)"),
])
def test_invalid_launch_records_give_data_guidance(launch, raw, error):  # noqa: F811
    stopped(launch)
    record = record_paths(launch)[-1]
    record.write_text(raw, encoding="utf-8")
    result = refused_unchanged(launch, spec_for(launch), "invalid launch record")
    assert result["error"] == (
        "stop evidence for %s: invalid launch record: %s%s; inspect %s and its retained evidence; "
        "%s will not change this record; owner must reconcile the invalid data before retrying"
        % (REVIEW, record, error, record, stop_command(launch)))


@pytest.mark.parametrize("extra,last", [(0, "resumed"), (1, "resumed"), (0, "not_running")])
def test_a_full_history_explains_the_limit_and_missing_archive_procedure(launch, extra, last):  # noqa: F811
    launch.start(cwd=str(launch.source))
    if last == "resumed":
        launch.run("resume", "--endpoint", REVIEW)
    else:
        launch.run("stop", "--endpoint", REVIEW)
    assert launch.records()[-1]["state"] == last
    paths = record_paths(launch)
    folder = paths[0].parent
    filler = launch.tmp / "unrelated-refusal.json"
    record = json.loads(paths[0].read_text(encoding="utf-8"))
    filler.write_text(json.dumps({**record, "session": "another-session", "state": "refused"}), encoding="utf-8")
    limit = handoff_module().hierarchy_launcher.MAX_RECORDS
    count = limit + extra
    for number in range(count - len(paths)):
        os.link(filler, folder / ("20000101T000000000000Z-%05d.json" % number))
    assert len(record_paths(launch)) == count
    assert launch.run("stop", "--endpoint", REVIEW, expect=2) == {
        "error": "launch record limit reached for " + REVIEW}
    result = refused_unchanged(launch, spec_for(launch), "launch record limit")
    assert result["error"] == (
        "stop evidence for %s: launch record limit %d reached (%d records); inspect %s; "
        "%s cannot append a stop record at this limit; docs/hierarchy-maintenance-runbook.md has no "
        "launch-record archive procedure yet; owner must preserve the history and arrange an "
        "archive/recovery procedure before retrying"
        % (REVIEW, limit, count, folder, stop_command(launch)))
