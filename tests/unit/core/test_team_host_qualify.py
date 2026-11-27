"""Host qualification record, status and the report-reading contract.

Parity covers legacy show/text_report decision class only. The record itself is
new: there is no legacy record or gate to replay.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import time
from codecs import BOM_UTF8
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
import stat
import threading
from types import SimpleNamespace

import pytest

from aegis_core import hosts
from aegis_core import team_host_qualify as qualify
from aegis_core.primitives import utc_stamp
from aegis_core.storage import file_lock
from aegis_core.team_host_qualify_report import PROBE_ROLES, role_retained
from conftest import symlink_or_skip


CLOCK = lambda: 1_700_000_000
VERSION = "1.2.3"
CANARY = "CANARY-SECRET-VALUE"


def _reader(value=VERSION):
    def read():
        return value
    return read


def _unexpected_version_read():
    pytest.fail("the version reader must not run")


def _spec():
    found = qualify.probe_runner_ids()
    assert len(found) == 1
    spec = hosts.get(found[0])
    assert spec.registration is not None
    assert spec.registration.kind == "native_cli"
    assert len(spec.binaries) == 1
    assert spec.binaries[0] in spec.aliases
    assert not spec.retired
    return spec


def _other():
    chosen = _spec().id
    for spec in hosts.HOSTS:
        if not spec.retired and spec.id != chosen:
            return spec
    raise AssertionError("registry has only one live host")


def _state(tmp_path):
    if not qualify.descriptor_supported():
        pytest.skip("descriptor custody requires POSIX")
    folder = tmp_path / "state"
    folder.mkdir(mode=0o700)
    os.chmod(folder, 0o700)
    return folder


def _work(tmp_path):
    folder = tmp_path / "work"
    folder.mkdir(exist_ok=True)
    return folder


def _line(row):
    return (json.dumps(row, sort_keys=True) + "\n").encode("utf-8")


def _attempt(verdict="REFUSED", **event_over):
    """One attempt from the producer's analyze_attempt, not a hand-written evidence map."""
    from tools.hierarchy_native import CODE_MODE, CODE_MODE_SAFE_OPTIONS
    from tools.hierarchy_probe_evidence import analyze_attempt

    attempt = {
        "id": "implementer-shell-worktree", "target": "worktree", "channel": "shell",
        "path": "/work/aegis-probe-n1", "nonce": "n1", "expected": verdict, "command": "probe",
    }
    if verdict == "UNAVAILABLE":
        return analyze_attempt(attempt, [], False, False, False, code_mode=CODE_MODE,
                               safe_options=CODE_MODE_SAFE_OPTIONS)
    helper = json.dumps({"nonce": "n1", "path": "/work/aegis-probe-n1", "ok": verdict == "ALLOWED", "errno": 13})
    event = {
        "exit_code": 0 if verdict == "ALLOWED" else 1, "status": "completed" if verdict == "ALLOWED" else "failed",
        "success": verdict == "ALLOWED", "command": "probe", "stdout": helper, "stderr": "",
        "aggregated_output": "", "path": "/rollout.jsonl", "line": 1, "sha256": "ab" * 32,
        "timestamp": "2020-01-01T00:00:00Z", "call_id": "c1", "source": "exec",
    }
    event.update(event_over)
    observations = [{"event": event, "match": "exact", "refusal_paths": ()}]
    return analyze_attempt(attempt, observations, True, verdict == "ALLOWED", False, code_mode=CODE_MODE,
                           safe_options=CODE_MODE_SAFE_OPTIONS)


def _nonce_only_allowed(*, wrapper=False):
    """Nonce file present, no matched event: the producer verdict is ALLOWED."""
    from tools.hierarchy_native import CODE_MODE, CODE_MODE_SAFE_OPTIONS
    from tools.hierarchy_probe_evidence import analyze_attempt

    attempt = {
        "id": "implementer-shell-worktree", "target": "worktree", "channel": "shell",
        "path": "/work/aegis-probe-n1", "nonce": "n1", "expected": "ALLOWED", "command": "probe",
    }
    observations = []
    if wrapper:
        event = _attempt()["evidence"]["event"]
        event["stdout"] = "producer witness\n" * 60
        observations.append({"event": event, "match": "untrusted", "refusal_paths": ()})
    return analyze_attempt(attempt, observations, True, True, False, code_mode=CODE_MODE,
                           safe_options=CODE_MODE_SAFE_OPTIONS)


def _permission(cwd):
    return {"type": "managed", "network": "restricted", "file_system": {"type": "restricted", "entries": [
        {"path": {"type": "special", "value": {"kind": "root"}}, "access": "read"},
        {"path": {"type": "path", "path": cwd}, "access": "write"},
    ]}}


def _sandbox(cwd):
    return {"type": "workspace-write", "writable_roots": [cwd], "network_access": False,
            "exclude_slash_tmp": True, "exclude_tmpdir_env_var": True}


def _producer_role(name, root, reviewer="auto_review", observed_reviewer="auto_review"):
    """Role row assembled from the probe's own builders."""
    from tools.hierarchy_native_probe import end_hold, hold_marks, multi_agent_check, read_turns, settings_check

    cwd = "/work"
    session, turn_a, turn_b = "sess-1", "turn-a", "turn-b"
    context = {
        "turn_id": turn_a, "model": "probe-model", "effort": "low", "cwd": cwd,
        "approval_policy": "on-request", "approvals_reviewer": observed_reviewer,
        "sandbox_policy": _sandbox(cwd), "permission_profile": _permission(cwd),
    }
    rollout = os.path.join(root, "rollout.jsonl")
    with open(rollout, "wb") as stream:
        stream.write(_line({"timestamp": "2020-01-01T00:00:00Z", "type": "session_meta",
                            "payload": {"id": session, "source": "exec"}}))
        stream.write(_line({"type": "event_msg", "payload": {"type": "task_started", "turn_id": turn_a}}))
        stream.write(_line({"timestamp": "2020-01-01T00:00:00Z", "type": "turn_context", "payload": context}))
        stream.write(_line({"type": "response_item", "payload": {"type": "additional_tools", "tools": [
            {"type": "function", "name": "functions.exec"}]}}))
    profile = {
        "model": "probe-model", "effort": "low", "cwd": cwd, "writable_roots": [], "add_dirs": [],
        "approval_policy": "on-request", "sandbox": "workspace-write", "disabled_features": [],
        "service_tier": None,
    }
    probe_settings = settings_check(rollout, session, profile, reviewer, turn_a)
    held = read_turns(rollout)[-1]
    with open(rollout, "ab") as stream:
        stream.write(_line({"type": "event_msg", "payload": {"type": "task_started", "turn_id": turn_b}}))
        wake_context = dict(context)
        wake_context["turn_id"] = turn_b
        stream.write(_line({"timestamp": "2020-01-01T00:00:01Z", "type": "turn_context", "payload": wake_context}))
        stream.write(_line({"type": "event_msg", "payload": {"type": "task_complete", "turn_id": turn_b}}))
    wake_settings = settings_check(rollout, session, profile, reviewer, turn_b)
    rows = read_turns(rollout)
    stopped = next(row for row in rows if row["turn_id"] == turn_a)
    resumed = rows[-1]
    marks = end_hold(hold_marks(root, "holdn"))
    sandbox = wake_settings.get("sandbox_policy") or {}
    wake_read = True
    kept = wake_settings["state"] == "PROFILE_MATCH" and sandbox.get("type") == profile["sandbox"]
    recovered = bool(wake_read and kept and resumed["completed"] and not stopped["completed"])
    log = {"stdout": os.path.join(root, "probe.stdout"), "stderr": os.path.join(root, "probe.stderr")}
    return {
        "role": name, "endpoint": "ep", "initiative": "init", "sandbox": profile["sandbox"], "shell": False,
        "session": session, "rollout": rollout,
        "steps": {
            "start": {"state": "bound", "launcher_exit": 0, "exit_code": 0, "session": session},
            "probe": {"state": "ran", "exit_code": 0, "timed_out": False, "turn_id": turn_a, "log": log},
            "hold": {"state": "stopped", "turn_context": held["context"], "stop": {"state": "stopped", "launcher_exit": 0},
                     "exit_code": None, "turn_id": held["turn_id"], "turn_completed": stopped["completed"],
                     "nonce": "holdn", "marks": marks, "log": log},
            "wake": {"state": "resumed", "publish": {"message_id": "probe-wake-1", "exit_code": 0},
                     "resume": {"state": "resumed", "launcher_exit": 0,
                                "wake": {"state": "read", "wake_id": "w1", "exit_code": 0, "timed_out": False}}},
        },
        "settings": {"probe": probe_settings, "wake": wake_settings},
        "attempts": [_attempt()],
        "recovery": {
            "stopped_turn_id": stopped["turn_id"], "stopped_turn_completed": stopped["completed"],
            "resumed_turn_id": resumed["turn_id"], "resumed_turn_completed": resumed["completed"],
            "wake_read": wake_read, "settings_kept": kept, "sandbox_policy": sandbox, "recovered": recovered,
        },
        "multi_agent": multi_agent_check(rollout, session),
    }


def _producer_root(*, extended=False):
    """Use the producer's ROOT reader against a recorded context."""
    from tools.hierarchy_native_probe import Runner

    folder = tempfile.mkdtemp(prefix="ta7b-root-")
    try:
        cid, turn, cwd = "cid-1", "turn-root", "/work"
        context = {
            "turn_id": turn, "model": "probe-model", "effort": "low", "cwd": cwd,
            "approval_policy": "on-request", "approvals_reviewer": "auto_review",
            "sandbox_policy": {"type": "read-only"},
            "permission_profile": {"type": "managed", "network": "restricted", "file_system": {
                "type": "restricted", "entries": [
                    {"path": {"type": "special", "value": {"kind": "root"}}, "access": "read"}]}},
        }
        if extended:
            for key in ("effort", "cwd", "approvals_reviewer", "sandbox_policy"):
                del context[key]
            entries = context["permission_profile"]["file_system"]["entries"]
            entries[0]["path"]["value"]["scope"] = {"include": ["/owner", None]}
            entries[0]["missing_path_behavior"] = ""
            entries.append({
                "path": {"type": "path", "path": "/work/read\npart"},
                "access": "read",
                "missing_path_behavior": "first\nsecond",
            })
        rollout = os.path.join(folder, "rollout.jsonl")
        with open(rollout, "wb") as stream:
            stream.write(_line({"timestamp": "2020-01-01T00:00:00Z", "type": "session_meta",
                                "payload": {"id": cid, "source": "exec"}}))
            stream.write(_line({"type": "event_msg", "payload": {"type": "task_started", "turn_id": turn}}))
            stream.write(_line({"timestamp": "2020-01-01T00:00:00Z", "type": "turn_context", "payload": context}))
            stream.write(_line({"type": "response_item", "payload": {"type": "additional_tools", "tools": [
                {"type": "function", "name": "functions.exec"}]}}))
        runner = SimpleNamespace(failures=[])
        result = Runner.root_settings(runner, {"rollout": rollout, "cid": cid})
        assert runner.failures == []
        return result
    finally:
        shutil.rmtree(folder)


def _role(name="implementer", attempts=None):
    folder = tempfile.mkdtemp(prefix="ta7b-probe-")
    try:
        role = _producer_role(name, folder)
    finally:
        shutil.rmtree(folder)
    if attempts is not None:
        role["attempts"] = attempts
    return role


def _report(spec, **overrides):
    from tools.hierarchy_native import UNCONFIRMED_SHAPE

    folder = tempfile.mkdtemp(prefix="ta7b-probe-")
    try:
        role = _producer_role("implementer", folder)
    finally:
        shutil.rmtree(folder)
    body = {
        "schema": qualify.REPORT_SCHEMA,
        "probe_root": "/probe",
        "probe_id": "probe-1",
        "started_at": "2020-01-01T00:00:00Z",
        spec.binaries[0]: {"path": "/usr/bin/host", "fake": False},
        "enforcement_claim": qualify.REAL_CLAIM,
        "turn_cap": 4,
        "login": {"argv": ["codex", "login", "--with-api-key"], "api_key_env": "AEGIS_PROBE_KEY", "exit_code": 0},
        "roles": [role],
        "root": None,
        "cleanup": {"worktree_removed": True, "auth_removed": True, "leftover_processes": [], "found_running": [],
                    "command": ["git", "-C", "/src", "worktree", "remove", "--force", "/wt"]},
        "shapes": {"apply_patch response_item": UNCONFIRMED_SHAPE},
        "home_codex": {"state": "unchanged", "folders": []},
        "state": "completed",
        "turns_used": 4,
        "finished_at": "2020-01-01T00:00:01Z",
        "summary": {"passed": True, "failures": [], "unexpected": [], "inconclusive": []},
    }
    body.update(overrides)
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _record(state, spec, payload=None, **kwargs):
    return qualify.record(
        str(state), spec.id, _report(spec) if payload is None else payload,
        version_reader=kwargs.pop("version_reader", _reader()),
        workspace=kwargs.pop("workspace", None), clock=kwargs.pop("clock", CLOCK), **kwargs)


def _path(state, spec):
    relative = qualify.record_relative(spec.id)
    assert relative is not None
    return state.joinpath(*relative)


def _lock_leaf(spec):
    """Basename of the stable per-host lock beside the receipt leaf."""
    relative = qualify.record_relative(spec.id)
    assert relative is not None
    leaf = relative[-1]
    assert leaf.endswith(".json") and "/" not in leaf and "\\" not in leaf
    return relative, leaf[:-len(".json")] + ".lock"


def _canonical(body, *, ensure_ascii=True):
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=ensure_ascii).encode("utf-8")


def _quiet(result):
    assert CANARY not in json.dumps(result)


_WORKER_BOUND = 10.0


class _WorkerFailure(Exception):
    """Both worker failures, so one thread cannot hide the other."""

    def __init__(self, errors):
        self.errors = tuple(errors)
        super().__init__("worker failures: %s" % (self.errors,))


def _run_workers(functions, bound=_WORKER_BOUND):
    """Start independent writers. Bound the start and the join. Propagate every exception."""
    outcomes = [None] * len(functions)
    failures = [None] * len(functions)
    started = threading.Barrier(len(functions))

    def invoke(index, function):
        try:
            started.wait(bound)
        except threading.BrokenBarrierError as exc:
            failures[index] = exc
            return
        try:
            outcomes[index] = function()
        except Exception as exc:
            failures[index] = exc

    threads = [threading.Thread(target=invoke, args=(index, function)) for index, function in enumerate(functions)]
    for thread in threads:
        thread.start()
    deadline = time.monotonic() + bound
    for thread in threads:
        thread.join(max(0.0, deadline - time.monotonic()))
    if any(thread.is_alive() for thread in threads):
        raise AssertionError("worker did not finish within %ss" % bound)
    found = [item for item in failures if item is not None]
    if found:
        raise _WorkerFailure(found)
    return outcomes


def _publish_pair(state, spec, payloads, reader):
    def attempt(payload):
        return qualify.record(str(state), spec.id, payload, version_reader=reader, clock=CLOCK)

    return _run_workers([lambda payload=payload: attempt(payload) for payload in payloads])


def _assert_one_winner(results, state, spec):
    assert sorted(item["reason"] for item in results) == ["receipt_recorded", "record_exists"]
    winner = next(item for item in results if item["reason"] == "receipt_recorded")
    loser = next(item for item in results if item["reason"] == "record_exists")
    assert "record" not in loser
    assert _path(state, spec).read_bytes() == _canonical(winner["record"])
    _quiet(winner)
    _quiet(loser)
    return winner


def _short_lock_wait(monkeypatch):
    if hasattr(qualify, "_LOCK_TIMEOUT"):
        monkeypatch.setattr(qualify, "_LOCK_TIMEOUT", 0.05)


def _hold_lock(state, spec):
    """Hold the per-host lock on another thread until the caller releases it."""
    relative, lock_name = _lock_leaf(spec)
    held = threading.Event()
    release = threading.Event()
    errors = []

    def occupy():
        try:
            with qualify.confined_file(str(state), relative) as handle:
                with file_lock(lock_name, timeout=2.0, dir_fd=handle.parent_fd):
                    held.set()
                    release.wait()
        except Exception as exc:
            errors.append(exc)
            held.set()

    thread = threading.Thread(target=occupy)
    thread.start()
    if not held.wait(2.0):
        release.set()
        thread.join(2.0)
        raise AssertionError("publication lock was not acquired")
    if errors:
        release.set()
        thread.join(2.0)
        raise errors[0]
    return thread, release


def _release_lock(thread, release):
    release.set()
    thread.join(2.0)
    assert not thread.is_alive()


def test_probe_runners_come_from_host_shape_without_a_fixed_id():
    spec = _spec()
    assert qualify.record_relative(spec.aliases[0]) == qualify.record_relative(spec.id)
    assert qualify.record_relative(_other().id) is not None
    assert qualify.record_relative("not-a-host") is None


def _replace_catalog_row(monkeypatch, updated):
    catalog = tuple(updated if row.id == updated.id else row for row in hosts.HOSTS)
    monkeypatch.setattr(hosts, "HOSTS", catalog)
    monkeypatch.setattr(hosts, "_BY_ID", {row.id: row for row in catalog})
    monkeypatch.setattr(hosts, "_BY_ALIAS", {alias: row.id for row in catalog for alias in row.aliases})


def _assert_report_receipt(state, spec, result):
    assert (result["status"], result["reason"], result["host"]) == ("unqualified", "receipt_recorded", spec.id)
    current = qualify.status(str(state), spec.id, version_reader=_reader())
    assert (current["status"], current["reason"], current["host"]) == ("unqualified", "receipt_current", spec.id)
    assert current["record"] == result["record"]
    with pytest.raises(qualify.HostUnqualified, match="^host is unqualified$") as caught:
        qualify.require_qualified(str(state), spec.id, version_reader=_unexpected_version_read)
    assert caught.value.code == "unqualified"


@pytest.mark.parametrize("field,value", [
    pytest.param("aliases", ("alternate-surface",), id="changed-aliases"),
    pytest.param("aliases", (), id="empty-aliases"),
    pytest.param("binaries", ("alternate-binary",), id="changed-binary"),
    pytest.param("binaries", ("primary-binary", "alternate-binary"), id="multiple-binaries"),
    pytest.param("binaries", (), id="empty-binaries"),
    pytest.param("registration", None, id="no-registration"),
    pytest.param("kind", "json_file", id="different-registration-kind"),
    pytest.param("argv", ("installer-wrapper",), id="changed-argv"),
    pytest.param("argv", (), id="empty-argv"),
])
def test_installer_metadata_does_not_remove_a_report_producer(tmp_path, monkeypatch, field, value):
    state, spec = _state(tmp_path), _spec()
    report = _report(spec, host=spec.id)
    changes = {field: value}
    if field in ("kind", "argv"):
        changes = {"registration": replace(spec.registration, **changes)}
    updated = replace(spec, **changes)
    _replace_catalog_row(monkeypatch, updated)

    assert qualify.probe_runner_ids() == (spec.id,)
    _assert_report_receipt(state, updated, _record(state, updated, report))


def test_installer_metadata_does_not_add_a_report_producer(monkeypatch):
    producer = _spec()
    other = _other()
    updated = replace(other, registration=producer.registration, binaries=producer.binaries,
                      aliases=producer.aliases)
    _replace_catalog_row(monkeypatch, updated)
    assert qualify.probe_runner_ids() == (producer.id,)


@pytest.mark.parametrize("row", hosts.HOSTS, ids=lambda row: row.id)
@pytest.mark.parametrize("key", [
    pytest.param("", id="undeclared"),
    pytest.param("synthetic-report-evidence", id="declared"),
])
def test_catalog_row_eligibility_and_evidence_follow_its_declaration(tmp_path, monkeypatch, row, key):
    state, original = _state(tmp_path), _spec()
    old_report = _report(original, host=row.id)
    updated = replace(row, team_report_producer=key)
    eligible = bool(key) and not row.retired
    expected = {original.id} - {row.id}
    if eligible:
        expected.add(row.id)
    _replace_catalog_row(monkeypatch, updated)

    assert qualify.probe_runner_ids() == tuple(spec.id for spec in hosts.HOSTS if spec.id in expected)
    before = qualify.status(str(state), row.id, version_reader=_unexpected_version_read)
    old = _record(state, updated, old_report, version_reader=_unexpected_version_read)
    assert before["host"] == old["host"] == row.id
    assert "record" not in before and "record" not in old
    assert not _path(state, updated).parent.exists()
    if not eligible:
        for result in (before, old):
            assert (result["status"], result["reason"]) == ("unqualified", "no_probe_runner")
        with pytest.raises(qualify.HostUnqualified, match="^host is unqualified$"):
            qualify.require_qualified(str(state), row.id, version_reader=_unexpected_version_read)
        return

    assert (before["status"], before["reason"]) == ("unqualified", "missing_record")
    assert (old["status"], old["reason"]) == ("refused", "report_rejected")
    body = json.loads(old_report)
    body[key] = body.pop(original.team_report_producer)
    _assert_report_receipt(state, updated, _record(state, updated, _canonical(body)))


@pytest.mark.parametrize("producer_key", ["", "alternate-producer"], ids=["cleared", "changed"])
def test_only_the_producer_declaration_controls_report_eligibility(tmp_path, monkeypatch, producer_key):
    state, spec = _state(tmp_path), _spec()
    original_report = _report(spec)
    updated = replace(spec, team_report_producer=producer_key)
    _replace_catalog_row(monkeypatch, updated)

    if not producer_key:
        assert spec.id not in qualify.probe_runner_ids()
        status = qualify.status(str(state), spec.id, version_reader=_reader())
        submission = _record(state, spec, original_report)
        for result in (status, submission):
            assert (result["status"], result["reason"]) == ("unqualified", "no_probe_runner")
            assert "record" not in result
        assert not _path(state, spec).parent.exists()
        return

    assert spec.id in qualify.probe_runner_ids()
    old = _record(state, spec, original_report)
    assert (old["status"], old["reason"]) == ("refused", "report_rejected")
    assert "record" not in old
    assert not _path(state, spec).parent.exists()
    report = json.loads(original_report)
    report[producer_key] = report.pop(spec.team_report_producer)
    _assert_report_receipt(state, updated, _record(state, updated, _canonical(report)))


def test_passing_report_records_owner_only_file(tmp_path):
    state, spec = _state(tmp_path), _spec()
    payload = _report(spec)
    submitted = json.loads(payload)
    result = _record(state, spec, payload, workspace=str(_work(tmp_path)))
    assert result["status"] == "unqualified"
    assert result["reason"] == "receipt_recorded"
    assert result["host"] == spec.id
    record = result["record"]
    assert record["v"] == 2
    assert record["enforcement_claim"] == qualify.REPORT_ONLY_CLAIM
    assert record["host"] == spec.id
    assert record["passed"] is True and record["fake"] is False
    assert record["version_source"] == "reader_at_record"
    assert record["host_version"] == VERSION
    assert record["version_note"] == qualify.VERSION_NOTE
    # Publication keeps the validated producer role, including the facts a later read re-checks.
    assert record["roles"] == {"implementer": submitted["roles"][0]}
    assert submitted["roles"][0]["steps"]["hold"]["turn_context"] is True
    assert "host" not in submitted
    assert record["recorded_at"] == utc_stamp(CLOCK())
    assert record["report_sha256"] == hashlib.sha256(payload).hexdigest()
    path = _path(state, spec)
    info = path.stat()
    assert stat.S_ISREG(info.st_mode)
    assert stat.S_IMODE(info.st_mode) == 0o600
    assert info.st_uid == os.getuid()
    assert json.loads(path.read_text(encoding="utf-8"))["probe_id"] == "probe-1"
    again = qualify.status(str(state), spec.aliases[0], version_reader=_reader(), workspace=str(_work(tmp_path)))
    assert again["status"] == "unqualified" and again["reason"] == "receipt_current"
    assert again["record"]["host"] == spec.id


def test_report_version_must_equal_the_reader_at_record_time(tmp_path):
    state, spec = _state(tmp_path), _spec()
    payload = _report(spec, host_version="9.9.9")

    def fail():
        raise OSError("unread")

    unread = _record(state, spec, payload, version_reader=fail)
    assert unread["status"] == "unqualified" and unread["reason"] == "version_unavailable"
    assert not (state / "host-qualification").exists()
    mismatch = _record(state, spec, payload, version_reader=_reader("9.9.8"))
    assert mismatch["status"] == "unqualified" and mismatch["reason"] == "version_changed"
    assert not (state / "host-qualification").exists()
    result = _record(state, spec, payload, version_reader=_reader("9.9.9"))
    assert result["reason"] == "receipt_recorded"
    assert result["record"]["version_source"] == "report"
    assert result["record"]["host_version"] == "9.9.9"
    assert "version_note" not in result["record"]
    status = qualify.status(str(state), spec.id, version_reader=_reader("9.9.9"))
    assert status["reason"] == "receipt_current"
    changed = qualify.status(str(state), spec.id, version_reader=_reader("9.9.8"))
    assert changed["status"] == "unqualified" and changed["reason"] == "version_changed"
    assert "record" not in changed


@pytest.mark.parametrize("value,reason", [
    (None, "version_unavailable"),
    ("", "version_unavailable"),
    (" 1.2.3", "version_unavailable"),
    ("a\nb", "version_multiline"),
    ("a\rb", "version_multiline"),
    ("a\u2028b", "version_multiline"),
])
def test_reader_failures_do_not_join_or_store(tmp_path, value, reason):
    state, spec = _state(tmp_path), _spec()
    result = _record(state, spec, version_reader=_reader(value))
    assert result["status"] == "unqualified" and result["reason"] == reason
    _quiet(result)
    assert "a b" not in json.dumps(result)
    assert not (state / "host-qualification").exists()


def test_reader_oserror_is_version_unavailable(tmp_path):
    state, spec = _state(tmp_path), _spec()

    def fail():
        raise OSError("down")

    result = _record(state, spec, version_reader=fail)
    assert result["reason"] == "version_unavailable"
    assert not (state / "host-qualification").exists()


def test_missing_record_is_unqualified(tmp_path):
    state, spec = _state(tmp_path), _spec()

    def fail():
        raise AssertionError("reader")

    found = qualify.status(str(state), spec.id, version_reader=fail)
    assert found["status"] == "unqualified" and found["reason"] == "missing_record"
    assert found["host"] == spec.id


def test_no_probe_runner_does_not_open_storage(tmp_path, monkeypatch):
    state = _state(tmp_path)
    other = _other()
    planted = state / "host-qualification"
    planted.mkdir(mode=0o700)
    (planted / (other.id + ".json")).write_text(CANARY, encoding="utf-8")

    def opened(*_args, **_kwargs):
        raise AssertionError("storage opened")

    monkeypatch.setattr(qualify, "confined_file", opened)
    found = qualify.status(str(state), other.id, version_reader=_reader())
    assert found["status"] == "unqualified" and found["reason"] == "no_probe_runner"
    _quiet(found)


def test_unknown_host_does_not_echo(tmp_path):
    state = _state(tmp_path)
    found = qualify.status(str(state), CANARY, version_reader=_reader())
    assert found["status"] == "refused" and found["reason"] == "unknown_host"
    assert found["host"] is None
    _quiet(found)


def test_unsupported_platform_creates_nothing(tmp_path, monkeypatch):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    monkeypatch.setattr(qualify, "descriptor_supported", lambda: False)
    found = qualify.record(str(state), _spec().id, b"{}", version_reader=_reader(), clock=CLOCK)
    assert found["status"] == "refused" and found["reason"] == "unsupported_platform"
    assert not (state / "host-qualification").exists()


def test_state_root_inside_workspace_is_untouched(tmp_path):
    work = _work(tmp_path)
    state = _state(work)
    found = _record(state, _spec(), workspace=str(work))
    assert found["reason"] == "record_inside_workspace"
    assert not (state / "host-qualification").exists()


@pytest.mark.parametrize("overrides", [
    {"summary": {"passed": True, "failures": [CANARY], "unexpected": [], "inconclusive": []}},
    {"summary": {"passed": False, "failures": [], "unexpected": [], "inconclusive": []}},
    {"state": "interrupted"},
    {"state": "refused"},
    {"schema": "other"},
    {"enforcement_claim": qualify.FAKE_CLAIM},
    {_spec().binaries[0]: {"path": "/probe/host-bin", "fake": True}},
    {"roles": [{"role": "writer", "attempts": [{"assessment": "UNEXPECTED"}]}]},
    {"roles": [{"role": "writer", "attempts": [{"assessment": "as_expected"}]},
               {"role": "writer", "attempts": [{"assessment": "as_expected"}]}]},
    {"probe_id": "bad id"},
    {"host_version": "9\n9"},
])
def test_rejected_reports_do_not_create_storage(tmp_path, overrides):
    state, spec = _state(tmp_path), _spec()
    found = _record(state, spec, _report(spec, **overrides))
    assert found["reason"] in ("report_rejected", "version_multiline")
    _quiet(found)
    if found["reason"] == "version_multiline":
        assert "9 9" not in json.dumps(found)
    assert not (state / "host-qualification").exists()


@pytest.mark.parametrize("raw", [
    b"",
    b"{",
    b'{"a": 1, "a": 2}',
    b'{"a": NaN}',
    b'{"a": Infinity}',
    b'{"a": 1e999}',
    b'{"a": -1e999}',
    b'{"v": ' + b"1" * 80 + b"}",
])
def test_malformed_reports_do_not_create_storage(tmp_path, raw):
    state, spec = _state(tmp_path), _spec()
    found = _record(state, spec, raw)
    assert found["reason"] == "report_malformed"
    assert not (state / "host-qualification").exists()


def test_oversized_report_is_malformed(tmp_path):
    state, spec = _state(tmp_path), _spec()
    found = _record(state, spec, b"{" + b" " * (qualify.MAX_REPORT_BYTES + 8))
    assert found["reason"] == "report_malformed"
    assert not (state / "host-qualification").exists()


_THOUSAND_ITEMS = b"[" + b"0," * 999 + b"0]"
_MALFORMED_SPELLINGS = [
    pytest.param(b'"CANARY-SECRET-VALUE","probe_id":"probe-1"', id="duplicate"),
    pytest.param(b"NaN", id="nan"),
    pytest.param(b"Infinity", id="infinity"),
    pytest.param(b"-Infinity", id="negative-infinity"),
    pytest.param(b"1e999", id="overflow"),
    pytest.param(b"-1e999", id="negative-overflow"),
    pytest.param(b'"\xff"', id="utf8"),
    pytest.param(b"[", id="syntax"),
    pytest.param(b"[" * 16 + b"0" + b"]" * 16, id="depth"),
    pytest.param(b"[" + b"0," * 1024 + b"0]", id="items"),
    pytest.param(b"[" + b",".join([_THOUSAND_ITEMS] * 8) + b"]", id="nodes"),
    pytest.param(b'"' + b"x" * 4097 + b'"', id="string"),
    pytest.param(b"1" * 65, id="atom"),
    pytest.param("bom", id="bom"),
    pytest.param("oversized", id="bytes"),
]


def _invalid_json(valid, spelling, limit):
    if spelling == "bom":
        return BOM_UTF8 + valid
    if spelling == "oversized":
        return valid.ljust(limit + 1, b" ")
    marker = b'"probe_id":"probe-1"'
    assert marker in valid
    return valid.replace(marker, b'"probe_id":' + spelling, 1)


def _assert_refused(result, reason, spec):
    assert (result["status"], result["reason"], result["host"]) == ("refused", reason, spec.id)
    assert "record" not in result
    _quiet(result)


def _assert_submission_refused(state, spec, work, raw, reason, version_reader):
    target = work / "report.json"
    target.write_bytes(raw)
    direct = _record(state, spec, raw, version_reader=version_reader)
    _assert_refused(direct, reason, spec)
    assert not _path(state, spec).parent.exists()
    delegated = qualify.record_file(str(state), spec.id, str(target), version_reader=version_reader,
                                    workspace=str(work), clock=CLOCK)
    _assert_refused(delegated, reason, spec)
    assert not _path(state, spec).parent.exists()
    assert target.read_bytes() == raw


@pytest.mark.parametrize("spelling", _MALFORMED_SPELLINGS)
def test_malformed_submission_has_fixed_refusals(tmp_path, spelling):
    state, spec, work = _state(tmp_path), _spec(), _work(tmp_path)
    report = _report(spec)
    malformed = _invalid_json(report, spelling, qualify.MAX_REPORT_BYTES)
    assert malformed != report
    _assert_submission_refused(state, spec, work, malformed, "report_malformed", _unexpected_version_read)
    assert qualify.show_report(str(work)) == (2, {"schema": qualify.REPORT_SCHEMA, "state": "refused"})

    (work / "report.json").write_bytes(report)
    assert qualify.show_report(str(work)) == (
        0, {"schema": qualify.REPORT_SCHEMA, "passed": True, "state": "completed", "fake": False},
    )
    stored = qualify.record_file(str(state), spec.id, str(work / "report.json"),
                                 version_reader=_reader(), workspace=str(work), clock=CLOCK)
    _assert_report_receipt(state, spec, stored)


def _assert_stored_spelling_refused(state, spec, report, valid, invalid):
    assert invalid != valid
    path = _path(state, spec)
    path.write_bytes(invalid)
    status = qualify.status(str(state), spec.id, version_reader=_unexpected_version_read)
    _assert_refused(status, "record_invalid", spec)
    assert path.read_bytes() == invalid

    newer = _reader("9.9.9")
    renewal = _record(state, spec, report, version_reader=newer)
    _assert_refused(renewal, "record_invalid", spec)
    assert path.read_bytes() == invalid

    path.write_bytes(valid)
    retried = _record(state, spec, report, version_reader=newer)
    assert (retried["status"], retried["reason"]) == ("unqualified", "receipt_recorded")
    assert retried["record"]["host_version"] == newer()
    current = qualify.status(str(state), spec.id, version_reader=newer)
    assert (current["status"], current["reason"]) == ("unqualified", "receipt_current")
    assert current["record"] == retried["record"]


@pytest.mark.parametrize("spelling", _MALFORMED_SPELLINGS)
def test_malformed_stored_receipt_cannot_be_read_or_renewed(tmp_path, spelling):
    state, spec = _state(tmp_path), _spec()
    report = _report(spec)
    assert _record(state, spec, report)["reason"] == "receipt_recorded"
    valid = _path(state, spec).read_bytes()
    invalid = _invalid_json(valid, spelling, qualify.MAX_RECORD_BYTES)
    _assert_stored_spelling_refused(state, spec, report, valid, invalid)


@pytest.mark.parametrize("violation", ["utf16", "node-budget"])
def test_schema_valid_stored_receipts_still_require_preflight(tmp_path, violation):
    state, spec = _state(tmp_path), _spec()
    report = _report(spec)
    assert _record(state, spec, report)["reason"] == "receipt_recorded"
    path = _path(state, spec)
    valid = path.read_bytes()
    body = json.loads(valid)

    if violation == "utf16":
        invalid = valid.decode("utf-8").encode("utf-16")
    else:
        template = body["roles"]["implementer"]
        attempt = template["attempts"][0]
        body["roles"] = {
            name: {
                **template,
                "role": name,
                "attempts": [dict(attempt, id=f"{name}-shell-{index}") for index in range(64)],
            }
            for name in sorted(PROBE_ROLES)
        }
        # Each attempt contributes its object and at least one node per key and value.
        attempt_nodes = sum(1 + 2 * len(item) for role in body["roles"].values()
                            for item in role["attempts"])
        assert attempt_nodes > 8000
        invalid = _canonical(body)
    assert json.loads(invalid) == body
    assert all(role_retained(name, role) for name, role in body["roles"].items())
    assert len(invalid) <= qualify.MAX_RECORD_BYTES

    _assert_stored_spelling_refused(state, spec, report, valid, invalid)


# Each supplementary code point uses one literal unit and two surrogate escapes.
_LONG_ENDPOINT = "\U0001f642" * 2049


def test_generated_receipt_rechecks_the_escaped_string_budget(tmp_path):
    state, spec, work = _state(tmp_path), _spec(), _work(tmp_path)
    report = json.loads(_report(spec))
    report["roles"][0]["endpoint"] = _LONG_ENDPOINT
    escaped = _canonical(report)
    literal = _canonical(report, ensure_ascii=False)
    assert json.loads(escaped) == json.loads(literal) == report
    assert len(escaped) < qualify.MAX_REPORT_BYTES

    _assert_submission_refused(state, spec, work, escaped, "report_malformed", _unexpected_version_read)
    assert qualify.show_report(str(work)) == (2, {"schema": qualify.REPORT_SCHEMA, "state": "refused"})

    _assert_submission_refused(state, spec, work, literal, "record_invalid", _reader())
    assert qualify.show_report(str(work)) == (
        0, {"schema": qualify.REPORT_SCHEMA, "passed": True, "state": "completed", "fake": False},
    )


def test_stored_role_endpoint_literal_is_current_and_escaped_is_refused(tmp_path):
    state, spec = _state(tmp_path), _spec()
    report = _report(spec)
    recorded = _record(state, spec, report)
    assert recorded["reason"] == "receipt_recorded"
    receipt = recorded["record"]
    role = receipt["roles"]["implementer"]
    role["endpoint"] = _LONG_ENDPOINT
    assert role_retained("implementer", role)
    literal = _canonical(receipt, ensure_ascii=False)
    escaped = _canonical(receipt)
    assert json.loads(escaped) == json.loads(literal) == receipt
    assert len(escaped) < qualify.MAX_RECORD_BYTES

    path = _path(state, spec)
    path.write_bytes(literal)
    current = qualify.status(str(state), spec.id, version_reader=_reader())
    assert (current["status"], current["reason"]) == ("unqualified", "receipt_current")
    assert current["record"] == receipt
    assert path.read_bytes() == literal

    _assert_stored_spelling_refused(state, spec, report, literal, escaped)


def test_second_record_leaves_bytes_unchanged(tmp_path):
    state, spec = _state(tmp_path), _spec()
    first = _record(state, spec)
    blob = _path(state, spec).read_bytes()
    second = _record(state, spec, _report(spec, probe_id="probe-2"))
    assert first["reason"] == "receipt_recorded"
    assert second["reason"] == "record_exists"
    assert _path(state, spec).read_bytes() == blob


def test_concurrent_records_keep_one_payload(tmp_path):
    """First creation: one winner, a record_exists loser, and the winner's bytes on disk."""
    state, spec = _state(tmp_path), _spec()
    payloads = [_report(spec, probe_id=name) for name in ("probe-a", "probe-b")]
    results = _publish_pair(state, spec, payloads, _reader())
    winner = _assert_one_winner(results, state, spec)
    assert winner["record"]["probe_id"] in ("probe-a", "probe-b")
    assert winner["record"]["host_version"] == VERSION
    assert not (state / "host-qualification" / (_lock_leaf(spec)[1])).is_symlink()


def test_concurrent_same_version_renewal_keeps_the_winner_bytes(tmp_path):
    """Same-version renewal is a separate decision from first creation."""
    state, spec = _state(tmp_path), _spec()
    assert _record(state, spec)["reason"] == "receipt_recorded"
    prior = _path(state, spec).read_bytes()
    payloads = [_report(spec, probe_id=name) for name in ("probe-a", "probe-b")]
    results = _publish_pair(state, spec, payloads, _reader("9.9.9"))
    winner = _assert_one_winner(results, state, spec)
    assert winner["record"]["host_version"] == "9.9.9"
    assert winner["record"]["probe_id"] in ("probe-a", "probe-b")
    assert _path(state, spec).read_bytes() != prior


def test_creation_timeout_writes_nothing_then_retries(tmp_path, monkeypatch):
    state, spec = _state(tmp_path), _spec()
    relative, _lock_name = _lock_leaf(spec)
    folder = state.joinpath(*relative[:-1])
    folder.mkdir(mode=0o700)
    os.chmod(folder, 0o700)
    _short_lock_wait(monkeypatch)
    calls = {"n": 0}

    def reader():
        calls["n"] += 1
        return "4.5.6"

    thread, release = _hold_lock(state, spec)
    try:
        found = _record(state, spec, _report(spec, probe_id="probe-a"), version_reader=reader)
    finally:
        _release_lock(thread, release)
    assert found["status"] == "refused" and found["reason"] == "record_busy"
    assert calls["n"] == 1
    assert not _path(state, spec).exists()
    dumped = json.dumps(found)
    assert ".lock" not in dumped and str(state) not in dumped and CANARY not in dumped
    retried = _record(state, spec, _report(spec, probe_id="probe-a"), version_reader=reader)
    assert retried["reason"] == "receipt_recorded"
    assert retried["record"]["host_version"] == "4.5.6"
    assert retried["record"]["probe_id"] == "probe-a"
    assert calls["n"] == 2


def test_renewal_timeout_keeps_prior_bytes_then_retries(tmp_path, monkeypatch):
    state, spec = _state(tmp_path), _spec()
    assert _record(state, spec)["reason"] == "receipt_recorded"
    prior = _path(state, spec).read_bytes()
    _short_lock_wait(monkeypatch)
    calls = {"n": 0}

    def reader():
        calls["n"] += 1
        return "9.9.9"

    thread, release = _hold_lock(state, spec)
    try:
        found = _record(state, spec, _report(spec, probe_id="probe-9"), version_reader=reader)
    finally:
        _release_lock(thread, release)
    assert found["status"] == "refused" and found["reason"] == "record_busy"
    assert calls["n"] == 1
    assert _path(state, spec).read_bytes() == prior
    dumped = json.dumps(found)
    assert ".lock" not in dumped and str(state) not in dumped and "probe-9" not in dumped
    retried = _record(state, spec, _report(spec, probe_id="probe-9"), version_reader=reader)
    assert retried["reason"] == "receipt_recorded"
    assert retried["record"]["host_version"] == "9.9.9"
    assert retried["record"]["probe_id"] == "probe-9"
    assert _path(state, spec).read_bytes() == _canonical(retried["record"])
    assert calls["n"] == 2


def test_lock_symlink_refuses_renewal_without_echo(tmp_path):
    state, spec = _state(tmp_path), _spec()
    assert _record(state, spec)["reason"] == "receipt_recorded"
    prior = _path(state, spec).read_bytes()
    _relative, lock_name = _lock_leaf(spec)
    lock = state.joinpath(*_relative[:-1], lock_name)
    if lock.exists() or lock.is_symlink():
        lock.unlink()
    secret = state / "secret"
    secret.write_text(CANARY, encoding="utf-8")
    symlink_or_skip(secret, lock)
    found = _record(state, spec, _report(spec, probe_id="probe-9"), version_reader=_reader("9.9.9"))
    assert found["reason"] == "record_unsafe"
    assert _path(state, spec).read_bytes() == prior
    assert secret.read_text(encoding="utf-8") == CANARY
    _quiet(found)
    assert ".lock" not in json.dumps(found)


class _ProbeError(Exception):
    pass


def test_publication_worker_failures_propagate_and_retry(tmp_path, monkeypatch):
    state, spec = _state(tmp_path), _spec()
    assert _record(state, spec)["reason"] == "receipt_recorded"
    prior = _path(state, spec).read_bytes()
    real = qualify.confined_file

    @contextmanager
    def wrapped(root, parts, create_parents=False):
        with real(root, parts, create_parents=create_parents) as handle:
            def publish_bytes(data, replace=False, mode=0o600):
                raise _ProbeError("publication refused")

            handle.publish_bytes = publish_bytes
            yield handle

    monkeypatch.setattr(qualify, "confined_file", wrapped)
    payloads = [_report(spec, probe_id=name) for name in ("probe-a", "probe-b")]
    with pytest.raises(_WorkerFailure) as caught:
        _publish_pair(state, spec, payloads, _reader("9.9.9"))
    assert len(caught.value.errors) == 2
    assert all(type(item) is _ProbeError for item in caught.value.errors)
    assert _path(state, spec).read_bytes() == prior
    monkeypatch.setattr(qualify, "confined_file", real)
    retried = _record(state, spec, _report(spec, probe_id="probe-9"), version_reader=_reader("9.9.9"))
    assert retried["reason"] == "receipt_recorded"
    assert retried["record"]["probe_id"] == "probe-9"
    assert _path(state, spec).read_bytes() == _canonical(retried["record"])


def test_weak_parent_and_mode_and_symlink_are_unsafe(tmp_path):
    state, spec = _state(tmp_path), _spec()
    folder = state / "host-qualification"
    folder.mkdir(mode=0o700)
    os.chmod(folder, 0o770)
    refused = _record(state, spec)
    assert refused["reason"] == "record_unsafe"
    assert list(folder.iterdir()) == []
    os.chmod(folder, 0o700)
    assert _record(state, spec)["reason"] == "receipt_recorded"
    path = _path(state, spec)
    os.chmod(path, 0o666)
    assert qualify.status(str(state), spec.id, version_reader=_reader())["reason"] == "record_unsafe"
    os.chmod(path, 0o400)
    assert qualify.status(str(state), spec.id, version_reader=_reader())["reason"] == "record_unsafe"
    os.chmod(path, 0o600)
    secret = state / "secret"
    secret.write_text(CANARY, encoding="utf-8")
    path.unlink()
    symlink_or_skip(secret, path)
    found = qualify.status(str(state), spec.id, version_reader=_reader())
    assert found["reason"] == "record_unsafe"
    _quiet(found)


def test_tampered_host_is_mismatch(tmp_path):
    state, spec = _state(tmp_path), _spec()
    assert _record(state, spec)["reason"] == "receipt_recorded"
    path = _path(state, spec)
    body = json.loads(path.read_text(encoding="utf-8"))
    body["host"] = _other().id
    path.write_text(json.dumps(body, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    os.chmod(path, 0o600)
    found = qualify.status(str(state), spec.id, version_reader=_reader())
    assert found["reason"] == "host_mismatch"
    assert found["host"] == spec.id


def test_require_qualified_raises_one_fixed_error(tmp_path):
    state, spec = _state(tmp_path), _spec()
    with pytest.raises(qualify.HostUnqualified) as caught:
        qualify.require_qualified(str(state), spec.id, version_reader=_reader())
    assert caught.value.code == "unqualified"
    assert str(caught.value) == "host is unqualified"
    assert caught.value.next_action["actor"] == "owner"
    assert "KIND" in caught.value.next_action["command"]
    assert _record(state, spec)["reason"] == "receipt_recorded"

    def no_read():
        pytest.fail("authorization queried a version for a report-only receipt")

    with pytest.raises(qualify.HostUnqualified) as again:
        qualify.require_qualified(str(state), spec.id, version_reader=no_read)
    assert again.value.code == "unqualified"
    assert str(again.value) == "host is unqualified"


def test_report_file_missing_symlink_and_retry(tmp_path):
    state, spec = _state(tmp_path), _spec()
    work = _work(tmp_path)
    missing = work / "missing.json"
    found = qualify.record_file(str(state), spec.id, str(missing), version_reader=_reader(), clock=CLOCK)
    assert found["reason"] == "report_missing"
    target = work / "report.json"
    target.write_bytes(_report(spec))
    link = work / "linked.json"
    symlink_or_skip(target, link)
    linked = qualify.record_file(str(state), spec.id, str(link), version_reader=_reader(), clock=CLOCK)
    assert linked["reason"] == "report_unreadable"
    assert not (state / "host-qualification").exists()
    stored = qualify.record_file(
        str(state), spec.id, str(target), version_reader=_reader(), workspace=str(work), clock=CLOCK)
    assert stored["reason"] == "receipt_recorded"


def test_relative_report_path_is_unreadable(tmp_path):
    state, spec = _state(tmp_path), _spec()
    found = qualify.record_file(str(state), spec.id, "report.json", version_reader=_reader(), clock=CLOCK)
    assert found["reason"] == "report_unreadable"
    assert not (state / "host-qualification").exists()


def _legacy_body(passed, fake, state, schema=None):
    return {
        "schema": schema or qualify.REPORT_SCHEMA,
        "probe_root": CANARY,
        "probe_id": "probe-1",
        "state": state,
        "codex": {"path": CANARY, "fake": fake},
        "turns_used": 1,
        "turn_cap": 2,
        "home_codex": {"state": "unchanged"},
        "roles": [{
            "role": "writer", "endpoint": "ep", "sandbox": "workspace-write", "shell": False,
            "session": "s", "steps": {"start": {"state": "ok"}, "probe": {"state": "ok"},
                                      "hold": {"state": "ok"}, "wake": {"state": "ok"}},
            "recovery": {"recovered": False}, "settings": {},
            "attempts": [{"channel": "shell", "target": CANARY, "verdict": "REFUSED",
                          "expected": "REFUSED", "assessment": "as_expected"}],
        }],
        "root": None,
        "login": None,
        "cleanup": {"worktree_removed": True, "auth_removed": True},
        "enforcement_claim": qualify.FAKE_CLAIM if fake else qualify.REAL_CLAIM,
        "summary": {"passed": passed, "failures": [] if passed else [CANARY],
                    "unexpected": [], "inconclusive": []},
    }


def _legacy_show(root):
    from tools import hierarchy_native_probe as probe
    try:
        code, _report = probe.show(SimpleNamespace(probe_root=str(root)))
    except probe.Refusal:
        return 2
    except (OSError, ValueError):
        return 2
    return code


@pytest.mark.parametrize("passed,fake,state", [
    (True, False, "completed"),
    (False, False, "completed"),
    (False, False, "interrupted"),
    (False, True, "completed"),
])
def test_show_and_text_match_legacy_decision_class(tmp_path, passed, fake, state):
    if not qualify.descriptor_supported():
        pytest.skip("descriptor custody requires POSIX")
    from tools import hierarchy_native_probe as probe
    root = tmp_path / "probe"
    root.mkdir(mode=0o700)
    body = _legacy_body(passed, fake, state)
    (root / "report.json").write_text(json.dumps(body), encoding="utf-8")
    assert qualify.show_report(str(root))[0] == _legacy_show(root)
    legacy = probe.text_report(body)
    rendered = qualify.text_report(body)
    assert ("NOT PASSED" in legacy) is (not passed)
    assert ("NOT PASSED" in rendered) is (not passed)
    assert ("PASSED" in rendered) is True
    assert ("(test fake)" in legacy) is fake
    assert ("fake yes" in rendered) is fake
    assert ("fake no" in rendered) is (not fake)
    assert CANARY not in rendered
    assert qualify.text_report(["nope"]) == "refused\n"


def test_show_wrong_schema_and_missing_report(tmp_path):
    if not qualify.descriptor_supported():
        pytest.skip("descriptor custody requires POSIX")
    root = tmp_path / "probe"
    root.mkdir(mode=0o700)
    assert qualify.show_report(str(root))[0] == 2
    assert _legacy_show(root) == 2
    (root / "report.json").write_text(json.dumps(_legacy_body(True, False, "completed", schema="nope")),
                                     encoding="utf-8")
    assert qualify.show_report(str(root))[0] == 2
    assert _legacy_show(root) == 2
    shown = qualify.show_report(str(root))[1]
    assert CANARY not in json.dumps(shown)


def test_empty_roles_attempts_and_contradictions_do_not_qualify(tmp_path):
    state, spec = _state(tmp_path), _spec()
    rows = (
        [],
        [{"role": "implementer", "attempts": []}],
        [{"role": "writer", "attempts": [_attempt()]}],
        [{"role": "implementer", "attempts": [
            {"assessment": "as_expected", "verdict": "ALLOWED", "expected": "REFUSED"}]}],
        [{"role": "implementer", "attempts": [
            {"assessment": "as_expected", "verdict": "REFUSED", "expected": "REFUSED",
             "evidence": {"contradiction": CANARY}}]}],
        [{"role": "implementer", "steps": {"start": {"state": "refused"}}, "attempts": [_attempt()]}],
        [{"role": "implementer", "attempts": [{"assessment": "as_expected"}]}],
    )
    for roles in rows:
        found = _record(state, spec, _report(spec, roles=roles))
        assert found["reason"] == "report_rejected"
        _quiet(found)
        assert not (state / "host-qualification").exists()


def test_hostile_verdicts_steps_and_report_facts_do_not_qualify(tmp_path):
    state, spec = _state(tmp_path), _spec()
    binary = spec.binaries[0]
    refused_present = _attempt()
    refused_present["evidence"] = {"nonce_file": True, "events": 1}
    present_dir = tmp_path / "present"
    present_dir.mkdir()
    present_state = _state(present_dir)
    present = _record(present_state, spec, _report(spec, roles=[_role(attempts=[refused_present])]))
    assert present["reason"] == "receipt_recorded"
    with pytest.raises(qualify.HostUnqualified):
        qualify.require_qualified(str(present_state), spec.id, version_reader=_reader())
    unknown = _attempt()
    unknown["evidence"] = {"nonce_file": False, "events": 1, "planted": True}
    attempts = (
        [{"assessment": "as_expected", "verdict": "NOT_ATTEMPTED", "expected": "NOT_ATTEMPTED",
          "evidence": {"nonce_file": False, "events": 0}}],
        [{"assessment": "as_expected", "verdict": "INCONCLUSIVE", "expected": "INCONCLUSIVE",
          "evidence": {"nonce_file": False, "events": 1, "contradiction": CANARY}}],
        [{"assessment": "as_expected", "verdict": "REFUSED", "expected": "REFUSED"}],
        [unknown],
    )
    for row in attempts:
        found = _record(state, spec, _report(spec, roles=[_role(attempts=row)]))
        assert found["reason"] == "report_rejected"
        _quiet(found)

    def reject(mutator):
        body_role = _role()
        mutator(body_role)
        found = _record(state, spec, _report(spec, roles=[body_role]))
        assert found["reason"] == "report_rejected"
        _quiet(found)

    reject(lambda row: row["steps"]["start"].__setitem__("state", "refused"))
    reject(lambda row: row["steps"]["probe"].__setitem__("state", "timed_out"))
    reject(lambda row: row["steps"]["hold"].__setitem__("state", "refused"))
    reject(lambda row: row["steps"]["wake"].__setitem__("state", "refused"))
    reject(lambda row: row["steps"]["wake"]["resume"]["wake"].__setitem__("state", "missed"))
    reject(lambda row: row["recovery"].__setitem__("recovered", False))
    reject(lambda row: row["settings"]["probe"].__setitem__("state", "PROFILE_HOLD"))
    reject(lambda row: row["settings"]["wake"].__setitem__("state", "UNAVAILABLE"))
    reject(lambda row: row["multi_agent"].__setitem__("state", "MULTI_AGENT_OFFERED"))
    reject(lambda row: row.__setitem__("helper_changed", {"before": {}, "after": {}}))
    reject(lambda row: row.__setitem__("folders_changed", [CANARY]))
    reject(lambda row: row.__setitem__("reader_error", {"error": CANARY}))
    reject(lambda row: row.__setitem__("profile_differences", [CANARY]))
    report_overrides = (
        {"home_codex": {"state": "changed"}},
        {"home_codex": {"state": "unknown"}},
        {"cleanup": {"worktree_removed": False, "auth_removed": True}},
        {"cleanup": {"worktree_removed": True, "auth_removed": True, "error": CANARY}},
        {"login": {"exit_code": 1}},
        {"login": {"mode": "existing", "error": CANARY}},
        {"root": {"read_only": False, "multi_agent": {"state": "MULTI_AGENT_OFF", "reasons": []}}},
        {"planted": {"fake": True}},
        {binary: {"path": "/usr/bin/host", "fake": False, "extra": True}},
    )
    for overrides in report_overrides:
        found = _record(state, spec, _report(spec, **overrides))
        assert found["reason"] == "report_rejected"
        _quiet(found)
    wide = json.loads(_report(spec))
    wide.update(("k%d" % index, index) for index in range(70))
    found = _record(state, spec, json.dumps(wide).encode("utf-8"))
    assert found["reason"] == "report_rejected"
    assert not (state / "host-qualification").exists()


def test_each_contract_role_can_qualify(tmp_path):
    state, spec = _state(tmp_path), _spec()
    for name in sorted(qualify._PROBE_ROLES):
        folder = state / name
        folder.mkdir(mode=0o700)
        os.chmod(folder, 0o700)
        payload = _report(spec, roles=[_role(name)])
        found = _record(folder, spec, payload)
        assert found["reason"] == "receipt_recorded"
        assert found["record"]["roles"] == {name: json.loads(payload)["roles"][0]}


def test_legacy_producer_report_has_no_host_and_a_mismatch_refuses(tmp_path):
    from tools import hierarchy_native_probe as probe

    state, spec = _state(tmp_path), _spec()
    body = json.loads(_report(spec))
    assert "host" not in body
    assert body["schema"] == probe.REPORT_SCHEMA
    assert body["enforcement_claim"] == probe.REAL_CLAIM
    assert set(probe.ROLES) >= {row["role"] for row in body["roles"]}
    assert _record(state, spec, _report(spec))["reason"] == "receipt_recorded"
    other = _record(state, spec, _report(spec, host=_other().id))
    assert other["reason"] == "report_rejected"
    _quiet(other)
    assert json.loads(_path(state, spec).read_text(encoding="utf-8"))["probe_id"] == "probe-1"
    alias = spec.id
    for name in spec.aliases:
        if name != spec.id:
            alias = name
            break
    fresh = tmp_path / "alias-state"
    fresh.mkdir(mode=0o700)
    os.chmod(fresh, 0o700)
    assert _record(fresh, spec, _report(spec, host=alias))["reason"] == "receipt_recorded"


def test_stored_empty_or_inconsistent_roles_are_invalid(tmp_path):
    state, spec = _state(tmp_path), _spec()
    assert _record(state, spec)["reason"] == "receipt_recorded"
    path = _path(state, spec)
    original = path.read_bytes()
    for roles in ({}, {"writer": "pass"}, {"implementer": "fail"}, {"implementer": "pass"}):
        body = json.loads(original)
        body["roles"] = roles
        path.write_text(json.dumps(body, sort_keys=True, separators=(",", ":")), encoding="utf-8")
        os.chmod(path, 0o600)
        found = qualify.status(str(state), spec.id, version_reader=_reader())
        assert found["reason"] == "record_invalid"
        assert "record" not in found
    path.write_bytes(original)
    os.chmod(path, 0o600)
    assert qualify.status(str(state), spec.id, version_reader=_reader())["reason"] == "receipt_current"


def test_missing_leaf_under_existing_directory_is_unqualified(tmp_path):
    state, spec = _state(tmp_path), _spec()
    folder = state / "host-qualification"
    folder.mkdir(mode=0o700)
    os.chmod(folder, 0o700)
    found = qualify.status(str(state), spec.id, version_reader=_reader())
    assert found["status"] == "unqualified" and found["reason"] == "missing_record"
    assert found["host"] == spec.id
    assert list(folder.iterdir()) == []


def test_workspace_inside_the_record_directory_is_refused(tmp_path):
    state, spec = _state(tmp_path), _spec()
    record_dir = state / "host-qualification"
    record_dir.mkdir(mode=0o700)
    os.chmod(record_dir, 0o700)
    found = _record(state, spec, workspace=str(record_dir))
    assert found["reason"] == "record_inside_workspace"
    assert list(record_dir.iterdir()) == []
    nested = record_dir / "role-root"
    nested.mkdir(mode=0o700)
    status = qualify.status(str(state), spec.id, version_reader=_reader(), workspace=str(nested))
    assert status["reason"] == "record_inside_workspace"
    assert list(record_dir.iterdir()) == [nested]


def test_renewal_replaces_only_a_changed_version(tmp_path):
    state, spec = _state(tmp_path), _spec()
    assert _record(state, spec)["reason"] == "receipt_recorded"
    blob = _path(state, spec).read_bytes()
    same = _record(state, spec, _report(spec, probe_id="probe-2"))
    assert same["reason"] == "record_exists"
    assert _path(state, spec).read_bytes() == blob
    changed = qualify.status(str(state), spec.id, version_reader=_reader("9.9.9"))
    assert changed["status"] == "unqualified" and changed["reason"] == "version_changed"
    renewed = _record(state, spec, _report(spec, probe_id="probe-9"), version_reader=_reader("9.9.9"))
    assert renewed["reason"] == "receipt_recorded"
    assert renewed["record"]["host_version"] == "9.9.9"
    assert renewed["record"]["probe_id"] == "probe-9"
    assert renewed["record"]["version_source"] == "reader_at_record"
    assert _path(state, spec).read_bytes() != blob
    info = _path(state, spec).stat()
    assert stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == os.getuid()
    again = _record(state, spec, _report(spec, probe_id="probe-10"), version_reader=_reader("9.9.9"))
    assert again["reason"] == "record_exists"
    assert json.loads(_path(state, spec).read_text(encoding="utf-8"))["probe_id"] == "probe-9"


def test_invalid_record_is_not_replaced_on_renewal(tmp_path):
    state, spec = _state(tmp_path), _spec()
    assert _record(state, spec)["reason"] == "receipt_recorded"
    path = _path(state, spec)
    path.write_bytes(b"{")
    os.chmod(path, 0o600)
    found = _record(state, spec, version_reader=_reader("9.9.9"))
    assert found["reason"] == "record_invalid"
    assert path.read_bytes() == b"{"


def test_renewal_refuses_when_the_record_bytes_change(tmp_path, monkeypatch):
    state, spec = _state(tmp_path), _spec()
    assert _record(state, spec)["reason"] == "receipt_recorded"
    blob = _path(state, spec).read_bytes()
    real = qualify.confined_file
    reads = {"n": 0}

    @contextmanager
    def wrapped(root, parts, create_parents=False):
        with real(root, parts, create_parents=create_parents) as handle:
            original = handle.read_bytes

            def read_bytes(limit):
                reads["n"] += 1
                data = original(limit)
                if reads["n"] >= 2:
                    return data + b"\n"
                return data

            handle.read_bytes = read_bytes
            yield handle

    monkeypatch.setattr(qualify, "confined_file", wrapped)
    found = _record(state, spec, _report(spec, probe_id="probe-9"), version_reader=_reader("9.9.9"))
    assert found["reason"] == "record_unsafe"
    assert _path(state, spec).read_bytes() == blob


def test_concurrent_renewal_keeps_one_complete_record(tmp_path):
    state, spec = _state(tmp_path), _spec()
    assert _record(state, spec)["reason"] == "receipt_recorded"
    gate = threading.Barrier(2)
    results = []

    def worker(probe_id, version):
        gate.wait()
        results.append(_record(
            state, spec, _report(spec, probe_id=probe_id), version_reader=_reader(version)))

    threads = [
        threading.Thread(target=worker, args=("probe-a", "2.0.0")),
        threading.Thread(target=worker, args=("probe-b", "3.0.0")),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    stored = json.loads(_path(state, spec).read_text(encoding="utf-8"))
    assert stored["probe_id"] in ("probe-1", "probe-a", "probe-b")
    assert stored["host_version"] in (VERSION, "2.0.0", "3.0.0")
    assert stored["passed"] is True and stored["fake"] is False
    info = _path(state, spec).stat()
    assert stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
    assert all(item["reason"] in ("receipt_recorded", "record_unsafe", "record_exists") for item in results)
    assert CANARY not in json.dumps(results)


def test_render_refuses_past_the_sixty_four_bound(tmp_path):
    spec = _spec()
    binary = spec.binaries[0]
    report = {"schema": qualify.REPORT_SCHEMA, "state": "completed", "summary": {"passed": True}}
    report.update(("k%d" % index, {"n": index}) for index in range(61))
    report[binary] = {"fake": True}
    assert len(report) > 64
    assert qualify.text_report(report) == "refused\n"
    roles = {"schema": qualify.REPORT_SCHEMA, "state": "completed",
             "summary": {"passed": True, "failures": [], "unexpected": [], "inconclusive": []},
             "roles": [{"role": "implementer"} for _ in range(65)]}
    assert qualify.text_report(roles) == "refused\n"
    if not qualify.descriptor_supported():
        pytest.skip("descriptor custody requires POSIX")
    root = tmp_path / "probe"
    root.mkdir(mode=0o700)
    (root / "report.json").write_text(json.dumps(report), encoding="utf-8")
    assert qualify.show_report(str(root))[0] == 2
    (root / "report.json").write_text(json.dumps(roles), encoding="utf-8")
    assert qualify.show_report(str(root))[0] == 2
    assert CANARY not in qualify.text_report(report)


def _reject(state, spec, mutator):
    role = _role()
    mutator(role)
    found = _record(state, spec, _report(spec, roles=[role]))
    assert found["reason"] == "report_rejected"
    _quiet(found)
    assert not (state / "host-qualification").exists()


def test_scalar_membership_returns_the_refusal(tmp_path):
    state, spec = _state(tmp_path), _spec()
    _reject(state, spec, lambda role: role["attempts"][0].__setitem__("verdict", []))
    _reject(state, spec, lambda role: role["steps"]["hold"]["marks"].__setitem__("done", []))
    _reject(state, spec, lambda role: role["steps"]["hold"]["marks"].__setitem__("release", []))


@pytest.mark.parametrize("mutate", [
    lambda role: role["attempts"][0]["evidence"]["event"].__setitem__("success", True),
    lambda role: role["steps"]["probe"].__setitem__("timed_out", True),
    lambda role: role["steps"]["probe"].__setitem__("exit_code", 1),
    lambda role: role["steps"]["hold"]["stop"].__setitem__("error", "stop failed"),
    lambda role: role["steps"]["hold"]["stop"].__setitem__("state", "refused"),
    lambda role: role["steps"]["hold"].__setitem__("turn_completed", True),
    lambda role: role["settings"]["probe"].__setitem__("model_check", "unchecked"),
    lambda role: role["settings"]["wake"].__setitem__("effort_check", "mismatch"),
    lambda role: role["settings"]["probe"].__setitem__("reasons", ["model unchecked"]),
    lambda role: role["multi_agent"].__setitem__("agent_tools", ["spawn_agent"]),
    lambda role: role["multi_agent"].__setitem__("tool_records", 0),
    lambda role: role["recovery"].__setitem__("wake_read", False),
    lambda role: role["recovery"].__setitem__("settings_kept", False),
    lambda role: role["recovery"].__setitem__("stopped_turn_completed", True),
    lambda role: role["recovery"].__setitem__("resumed_turn_completed", False),
    lambda role: role.__setitem__("shell", True) or role.__setitem__("attempts", [_attempt("UNAVAILABLE")]),
    lambda role: role.__setitem__("sandbox", "read-only") or role.__setitem__("attempts", [_attempt("ALLOWED")]),
    lambda role: role.__setitem__("attempts", [_attempt("ALLOWED")]) or role["attempts"][0].__setitem__("target", "gitdir"),
    lambda role: role.__setitem__("attempts", [_attempt("ALLOWED")]) or role["attempts"][0]["evidence"].__setitem__("events", 0),
    lambda role: role["attempts"][0]["evidence"].__setitem__("nonce_file", True),
    lambda role: role["attempts"][0]["evidence"].__setitem__("events", 0),
    lambda role: role["attempts"][0]["evidence"].pop("event"),
    lambda role: role["attempts"][0]["evidence"].__setitem__("contradiction", "split"),
    lambda role: role["attempts"][0]["evidence"].__setitem__("strength", "noted"),
    lambda role: role["attempts"][0]["evidence"].__setitem__("note", "noted"),
    lambda role: role.__setitem__("attempts", [_attempt("ALLOWED")]) or role["attempts"][0]["evidence"].__setitem__("nonce_file", False),
    lambda role: role.__setitem__("attempts", [_attempt("ALLOWED")]) or role["attempts"][0]["evidence"].__setitem__("strength", "noted"),
    lambda role: role.__setitem__("attempts", [_attempt("ALLOWED")]) or role["attempts"][0]["evidence"].__setitem__("contradiction", "split"),
    lambda role: role.__setitem__("attempts", [_attempt("ALLOWED")]) or role["attempts"][0].__setitem__("target", "codex_home"),
    lambda role: role.__setitem__("attempts", [_attempt("UNAVAILABLE")]) or role["attempts"][0].__setitem__("channel", "apply_patch"),
    lambda role: role.__setitem__("attempts", [_attempt("UNAVAILABLE")]) or role["attempts"][0]["evidence"].__setitem__("events", 1),
    lambda role: role.__setitem__("attempts", [_attempt("UNAVAILABLE")]) or role["attempts"][0]["evidence"].__setitem__("nonce_file", True),
    lambda role: role.__setitem__("attempts", [_attempt("UNAVAILABLE")]) or role["attempts"][0]["evidence"].pop("strength", None),
    lambda role: role.__setitem__("attempts", [_attempt("UNAVAILABLE")]) or role["attempts"][0]["evidence"].__setitem__("strength", "other"),
    lambda role: role.__setitem__("attempts", [_attempt("UNAVAILABLE")]) or role["attempts"][0]["evidence"].__setitem__("contradiction", "split"),
    lambda role: role["attempts"][0].__setitem__("expected", "ALLOWED"),
    lambda role: role["steps"]["probe"].__setitem__("error", "probe failed"),
    lambda role: role["steps"]["hold"]["stop"].__setitem__("unresolved_groups", ["left"]),
    lambda role: role["steps"]["start"].__setitem__("error", "start failed"),
    lambda role: role["steps"]["wake"]["resume"].__setitem__("error", "resume failed"),
    lambda role: role["steps"]["wake"]["publish"].__setitem__("error", "publish failed"),
    lambda role: role["multi_agent"].__setitem__("unknown_tools", ["other"]),
])
def test_schema_valid_contradictions_store_a_receipt(tmp_path, mutate):
    state, spec = _state(tmp_path), _spec()
    role = _role()
    mutate(role)
    found = _record(state, spec, _report(spec, roles=[role]))
    assert found["status"] == "unqualified" and found["reason"] == "receipt_recorded"
    assert found["record"]["v"] == 2
    assert found["record"]["enforcement_claim"] == qualify.REPORT_ONLY_CLAIM
    assert (state / "host-qualification").exists()
    with pytest.raises(qualify.HostUnqualified):
        qualify.require_qualified(str(state), spec.id, version_reader=_reader())


def test_missing_required_check_is_rejected(tmp_path):
    state, spec = _state(tmp_path), _spec()
    _reject(state, spec, lambda role: role["settings"]["probe"].pop("model_check"))
    _reject(state, spec, lambda role: role["settings"]["wake"].pop("effort_check"))


def _receipt(parent, spec, payload):
    state = _state(parent)
    found = _record(state, spec, payload)
    assert found["status"] == "unqualified" and found["reason"] == "receipt_recorded"
    assert (state / "host-qualification").exists()
    with pytest.raises(qualify.HostUnqualified):
        qualify.require_qualified(str(state), spec.id, version_reader=_reader())
    return found


def test_home_and_cleanup_variants_store_a_receipt(tmp_path):
    spec = _spec()
    folder = {"path": "/home/owner", "before": "aaa", "after": "bbb", "errors": [], "state": "changed"}
    same = {"path": "/home/owner", "before": "aaa", "after": "bbb", "errors": ["missed"], "state": "unchanged"}
    cleanup = {"worktree_removed": True, "auth_removed": True, "leftover_processes": [4], "found_running": [],
               "command": ["git", "-C", "/src", "worktree", "remove", "--force", "/wt"]}
    payloads = [
        _report(spec, home_codex={"state": "unchanged", "folders": [folder]}),
        _report(spec, home_codex={"state": "unchanged", "folders": [same]}),
        _report(spec, cleanup=cleanup),
        _report(spec, cleanup=dict(cleanup, leftover_processes=[], error="left")),
        _report(spec, cleanup=dict(cleanup, leftover_processes=[], auth_error="auth left")),
        _report(spec, cleanup=dict(cleanup, leftover_processes=[], login_left=["session"])),
        _report(spec, cleanup=dict(cleanup, leftover_processes=[], unresolved_custody=[
            {"base": None, "endpoint": None, "reason": "left"}])),
        _report(spec, login={"mode": "existing", "auth_file": "/home/owner/auth.json",
                             "codex_login_called": False, "auth_file_sha256_before": None,
                             "cleanup": "removed", "error": "still there"}),
    ]
    root = _producer_root()
    payloads.append(_report(spec, root=root))
    agent = dict(root["multi_agent"])
    for mutated in (
        {**agent, "agent_tools": ["spawn_agent"]},
        {**agent, "tool_records": 0},
    ):
        body = dict(root)
        body["multi_agent"] = mutated
        payloads.append(_report(spec, root=body))
    for index, payload in enumerate(payloads):
        parent = tmp_path / ("case-%s" % index)
        parent.mkdir()
        _receipt(parent, spec, payload)


def _location_only(role):
    event = role["attempts"][0]["evidence"]["event"]
    for key in ("exit_code", "status", "success"):
        event.pop(key, None)


def _unavailable_with_event(role):
    role["attempts"] = [_attempt("UNAVAILABLE")]
    role["attempts"][0]["evidence"]["events"] = 1
    role["attempts"][0]["evidence"]["event"] = {
        "path": "/rollout.jsonl", "line": 1, "sha256": "ab" * 32,
        "timestamp": "2020-01-01T00:00:00Z", "source": "exec",
        "exit_code": 0, "status": "completed", "success": True,
    }


def _allowed_outside(role):
    role["shell"] = True
    attempt = _attempt("ALLOWED")
    attempt["path"] = "/etc/aegis-probe-n1"
    role["attempts"] = [attempt]


def _wake_tier_missing(role):
    role["settings"]["wake"]["requested_tier"] = "flex"
    role["settings"]["wake"]["served_tier"] = None


@pytest.mark.parametrize("mutate", [
    lambda role: role["steps"]["hold"]["stop"].__setitem__("launcher_exit", 1),
    lambda role: role["steps"]["start"].__setitem__("launcher_exit", 1),
    lambda role: role["steps"]["wake"]["resume"].__setitem__("launcher_exit", 1),
    lambda role: role["steps"]["start"].__setitem__("exit_code", 1),
    lambda role: role["steps"]["wake"]["resume"]["wake"].__setitem__("exit_code", 1),
    lambda role: role["settings"]["probe"].__setitem__("approvals_reviewer", "other"),
    lambda role: role["settings"]["wake"].__setitem__("approvals_reviewer", "other"),
    lambda role: role["settings"]["probe"].__setitem__("served_tier", "priority"),
    _wake_tier_missing,
    lambda role: role["recovery"].__setitem__("stopped_turn_id", None),
    lambda role: role["recovery"].__setitem__("resumed_turn_id", None),
    lambda role: role["multi_agent"].__setitem__("reasons", ["the session was offered sub-agent tools"]),
    _location_only,
    _unavailable_with_event,
    _allowed_outside,
], ids=[
    "hold-launcher-exit", "start-launcher-exit", "resume-launcher-exit",
    "start-exit-code", "wake-exit-code", "probe-reviewer", "wake-reviewer",
    "probe-tier", "wake-tier", "stopped-turn-id", "resumed-turn-id",
    "agent-reasons", "location-only-refused", "unavailable-event", "allowed-outside",
])
def test_schema_valid_role_facts_store_a_receipt(tmp_path, mutate):
    state, spec = _state(tmp_path), _spec()
    role = _role()
    mutate(role)
    found = _record(state, spec, _report(spec, roles=[role]))
    assert found["reason"] == "receipt_recorded"
    with pytest.raises(qualify.HostUnqualified):
        qualify.require_qualified(str(state), spec.id, version_reader=_reader())


@pytest.mark.parametrize("wrapper", [False, True])
def test_nonce_only_allowed_records(tmp_path, wrapper):
    state, spec = _state(tmp_path), _spec()
    role = _role(attempts=[_nonce_only_allowed(wrapper=wrapper)])
    role["shell"] = True
    found = _record(state, spec, _report(spec, roles=[role]))
    assert found["reason"] == "receipt_recorded"
    stored = found["record"]["roles"]["implementer"]["attempts"][0]
    assert stored["verdict"] == "ALLOWED"
    assert stored["evidence"]["nonce_file"] is True
    assert stored["evidence"]["events"] == 0
    assert ("event" in stored["evidence"]) is wrapper
    if wrapper:
        assert len(stored["evidence"]["output"].splitlines()) == 60
    again = qualify.status(str(state), spec.id, version_reader=_reader())
    assert again["reason"] == "receipt_current"


def test_shell_refusal_with_exit_zero_records(tmp_path):
    state, spec = _state(tmp_path), _spec()
    role = _role(attempts=[_attempt("REFUSED", exit_code=0)])
    assert role["attempts"][0]["evidence"]["event"]["exit_code"] == 0
    assert role["attempts"][0]["evidence"]["event"]["status"] == "failed"
    found = _record(state, spec, _report(spec, roles=[role]))
    assert found["reason"] == "receipt_recorded"
    again = qualify.status(str(state), spec.id, version_reader=_reader())
    assert again["reason"] == "receipt_current"


def test_null_reviewer_records(tmp_path):
    state, spec = _state(tmp_path), _spec()
    folder = tempfile.mkdtemp(prefix="ta7b-probe-")
    try:
        role = _producer_role("implementer", folder, reviewer="none", observed_reviewer=None)
    finally:
        shutil.rmtree(folder)
    assert role["settings"]["probe"]["approvals_reviewer"] is None
    assert role["settings"]["probe"]["state"] == "PROFILE_MATCH"
    assert role["settings"]["wake"]["approvals_reviewer"] is None
    found = _record(state, spec, _report(spec, roles=[role]))
    assert found["reason"] == "receipt_recorded"
    again = qualify.status(str(state), spec.id, version_reader=_reader())
    assert again["reason"] == "receipt_current"


def test_read_wake_timeout_records(tmp_path):
    state, spec = _state(tmp_path), _spec()
    role = _role()
    role["steps"]["wake"]["resume"]["wake"]["timed_out"] = True
    found = _record(state, spec, _report(spec, roles=[role]))
    assert found["reason"] == "receipt_recorded"
    assert found["record"]["roles"]["implementer"]["steps"]["wake"]["resume"]["wake"]["timed_out"] is True
    again = qualify.status(str(state), spec.id, version_reader=_reader())
    assert again["reason"] == "receipt_current"


def _eight_attempts(name):
    attempts = []
    for index in range(8):
        attempt = _attempt()
        attempt["id"] = "%s-shell-%d" % (name, index)
        attempt["evidence"]["output"] = attempt["evidence"]["output"] + "\n" + ("n" * 1500)
        attempts.append(attempt)
    return attempts


def test_seven_roles_eight_attempts_fit_the_record_budget(tmp_path, monkeypatch):
    from tools import hierarchy_native_probe as probe

    state, spec = _state(tmp_path), _spec()
    names = ("implementer", "integrator", "reviewer", "front-door", "orchestrator", "router", "decider")
    roles = []
    for name in names:
        folder = tempfile.mkdtemp(prefix="ta7b-probe-")
        try:
            role = _producer_role(name, folder)
        finally:
            shutil.rmtree(folder)
        role["attempts"] = _eight_attempts(name)
        roles.append(role)
    run_fields = json.loads(_report(spec))
    runner = SimpleNamespace(
        login=lambda: run_fields["login"], cleanup=lambda: run_fields["cleanup"],
        role=lambda row: row, failures=[], capped=False, turns_used=28,
    )
    monkeypatch.setattr("tools.hierarchy_native_probe.Runner", lambda *_args: runner)
    monkeypatch.setattr("tools.hierarchy_native_probe.home_codexes", lambda _fake: [])
    root = tmp_path / "producer"
    root.mkdir()
    code, emitted = probe.run_locked({"probe_id": "probe-7", "roles": roles, "root": None},
                                     28, "AEGIS_PROBE_KEY", "/usr/bin/host", False, root)
    assert code == 0
    payload = (root / "report.json").read_bytes()
    assert len(payload) <= qualify.MAX_REPORT_BYTES
    found = _record(state, spec, payload)
    assert found["reason"] == "receipt_recorded"
    encoded = _path(state, spec).read_bytes()
    assert len(encoded) <= qualify.MAX_RECORD_BYTES
    assert found["record"]["roles"] == {row["role"]: row for row in emitted["roles"]}
    changed = qualify.status(str(state), spec.id, version_reader=_reader("9.9.9"))
    assert changed["reason"] == "version_changed"
    renewed = _record(state, spec, payload, version_reader=_reader("9.9.9"))
    assert renewed["reason"] == "receipt_recorded"
    assert renewed["record"]["host_version"] == "9.9.9"
    assert renewed["record"]["roles"] == found["record"]["roles"]


def test_record_budget_boundary(tmp_path, monkeypatch):
    state, spec = _state(tmp_path), _spec()
    payload = _report(spec)
    assert _record(state, spec, payload)["reason"] == "receipt_recorded"
    encoded = _path(state, spec).read_bytes()
    budget = qualify.MAX_RECORD_BYTES
    exact = tmp_path / "exact"
    exact.mkdir(mode=0o700)
    os.chmod(exact, 0o700)
    monkeypatch.setattr(qualify, "MAX_RECORD_BYTES", len(encoded))
    assert _record(exact, spec, payload)["reason"] == "receipt_recorded"
    tight = tmp_path / "tight"
    tight.mkdir(mode=0o700)
    os.chmod(tight, 0o700)
    monkeypatch.setattr(qualify, "MAX_RECORD_BYTES", len(encoded) - 1)
    refused = _record(tight, spec, payload)
    assert refused["reason"] == "record_invalid"
    assert not (tight / "host-qualification").exists()
    monkeypatch.setattr(qualify, "MAX_RECORD_BYTES", budget)
    path = _path(state, spec)
    path.write_bytes(b"x" * (budget + 1))
    os.chmod(path, 0o600)
    found = qualify.status(str(state), spec.id, version_reader=_reader())
    assert found["reason"] == "record_invalid"
    assert "record" not in found
    other = tmp_path / "over-report"
    other.mkdir(mode=0o700)
    os.chmod(other, 0o700)
    malformed = _record(other, spec, b"{" * (qualify.MAX_REPORT_BYTES + 1))
    assert malformed["reason"] == "report_malformed"


def test_root_write_unknown_tools_and_reasons_store_a_receipt(tmp_path):
    spec = _spec()
    root = _producer_root()
    cases = []
    write = json.loads(json.dumps(root))
    write["read_only"] = True
    entry = json.loads(json.dumps(write["observed_permissions"]["entries"][0]))
    entry["access"] = "write"
    write["observed_permissions"]["entries"].append(entry)
    cases.append(write)
    unknown = json.loads(json.dumps(root))
    unknown["multi_agent"]["unknown_tools"] = ["other"]
    cases.append(unknown)
    reasons = json.loads(json.dumps(root))
    reasons["multi_agent"]["reasons"] = ["the session was offered sub-agent tools"]
    cases.append(reasons)
    for index, body in enumerate(cases):
        fresh_dir = tmp_path / ("root-fact-%s" % index)
        fresh_dir.mkdir()
        _receipt(fresh_dir, spec, _report(spec, root=body))


def test_stored_missing_proof_is_rechecked(tmp_path):
    state, spec = _state(tmp_path), _spec()
    assert _record(state, spec)["reason"] == "receipt_recorded"
    path = _path(state, spec)
    body = json.loads(path.read_text(encoding="utf-8"))
    body["roles"]["implementer"]["steps"]["hold"]["stop"]["launcher_exit"] = 1
    path.write_text(json.dumps(body, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    os.chmod(path, 0o600)
    found = qualify.status(str(state), spec.id, version_reader=_reader())
    assert found["reason"] == "receipt_current"
    assert found["record"]["roles"]["implementer"]["steps"]["hold"]["stop"]["launcher_exit"] == 1
    with pytest.raises(qualify.HostUnqualified):
        qualify.require_qualified(str(state), spec.id, version_reader=_reader())


def test_stored_contradiction_is_rechecked(tmp_path):
    state, spec = _state(tmp_path), _spec()
    payload = _report(spec)
    assert _record(state, spec, payload)["reason"] == "receipt_recorded"
    path = _path(state, spec)
    body = json.loads(path.read_text(encoding="utf-8"))
    assert body["roles"]["implementer"]["attempts"][0]["evidence"]["event"]["success"] is False
    body["roles"]["implementer"]["attempts"][0]["evidence"]["event"]["success"] = True
    path.write_text(json.dumps(body, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    os.chmod(path, 0o600)
    found = qualify.status(str(state), spec.id, version_reader=_reader())
    assert found["reason"] == "receipt_current"
    assert found["record"]["roles"]["implementer"]["attempts"][0]["evidence"]["event"]["success"] is True
    with pytest.raises(qualify.HostUnqualified):
        qualify.require_qualified(str(state), spec.id, version_reader=_reader())


def test_v1_bytes_confer_no_authority_and_are_not_replaced(tmp_path):
    state, spec = _state(tmp_path), _spec()
    assert _record(state, spec)["reason"] == "receipt_recorded"
    path = _path(state, spec)
    body = json.loads(path.read_text(encoding="utf-8"))
    body["v"] = 1
    body["enforcement_claim"] = qualify.REAL_CLAIM
    raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    path.write_bytes(raw)
    os.chmod(path, 0o600)
    found = qualify.status(str(state), spec.id, version_reader=_reader())
    assert found["reason"] == "record_invalid"
    assert "record" not in found
    assert path.read_bytes() == raw
    renewed = _record(state, spec, version_reader=_reader("9.9.9"))
    assert renewed["reason"] == "record_invalid"
    assert path.read_bytes() == raw
    with pytest.raises(qualify.HostUnqualified):
        qualify.require_qualified(str(state), spec.id, version_reader=_reader())


@pytest.mark.parametrize("root_only", [True, False])
def test_producer_root_receipt_records_reads_and_renews(tmp_path, monkeypatch, root_only):
    from tools import hierarchy_native_probe as probe

    state, spec = _state(tmp_path), _spec()
    observation = _producer_root(extended=True)
    assert observation["settings"]["effort"] is None
    assert observation["settings"]["sandbox_policy"] is None
    permissions = observation["observed_permissions"]["entries"]
    assert permissions[0]["special_fields"] == {
        "scope": {"include": ["/owner", None]},
    }
    assert permissions[0]["missing_path_behavior"] == ""
    assert permissions[1]["path_or_special"] == "/work/read\npart"
    assert permissions[1]["missing_path_behavior"] == "first\nsecond"
    fields = json.loads(_report(spec))
    roles = [] if root_only else fields["roles"]
    runner = SimpleNamespace(
        login=lambda: fields["login"], cleanup=lambda: fields["cleanup"],
        role=lambda row: row, root_settings=lambda _row: observation,
        failures=[], capped=False, turns_used=0 if root_only else 4,
    )
    monkeypatch.setattr("tools.hierarchy_native_probe.Runner", lambda *_args: runner)
    monkeypatch.setattr("tools.hierarchy_native_probe.home_codexes", lambda _fake: [])
    producer = tmp_path / "producer"
    producer.mkdir()
    code, report = probe.run_locked({"probe_id": "root-probe", "roles": roles, "root": {}},
                                    4, "AEGIS_PROBE_KEY", "/usr/bin/host", False, producer)
    assert code == 0
    assert (report["login"] is None) is root_only
    raw = (producer / "report.json").read_bytes()
    first = _record(state, spec, raw)
    assert (first["status"], first["reason"]) == ("unqualified", "receipt_recorded")
    body = first["record"]
    assert body["report_sha256"] == hashlib.sha256(raw).hexdigest()
    assert body["roles"] == {row["role"]: row for row in roles}
    assert ("root_only" in body) is root_only
    if root_only:
        assert body["root_only"] is True
    before = _path(state, spec).read_bytes()
    assert qualify.status(str(state), spec.id, version_reader=_reader())["record"] == body
    assert _path(state, spec).read_bytes() == before
    assert _record(state, spec, raw)["reason"] == "record_exists"
    assert _path(state, spec).read_bytes() == before
    newer = _record(state, spec, raw, version_reader=_reader("9.9.9"))
    assert newer["reason"] == "receipt_recorded"
    assert newer["record"] == {**body, "host_version": "9.9.9"}
    assert _path(state, spec).read_bytes() != before
    current = qualify.status(str(state), spec.id, version_reader=_reader("9.9.9"))
    assert current["reason"] == "receipt_current"
    assert current["record"] == newer["record"]
    with pytest.raises(qualify.HostUnqualified):
        qualify.require_qualified(str(state), spec.id, version_reader=_reader("9.9.9"))


@pytest.mark.parametrize("changes", [
    {"roles": [], "login": None, "root": None},
    {"roles": [], "login": None, "root": {}},
    {"roles": [], "login": None, "root": {"read_only": True}},
    {"login": None},
])
def test_import_requires_one_complete_producer_variant(tmp_path, changes):
    state, spec = _state(tmp_path), _spec()
    assert _record(state, spec, _report(spec, **changes))["reason"] == "report_rejected"
    assert not _path(state, spec).exists()


def test_root_only_rejects_login_and_malformed_observations(tmp_path):
    state, spec = _state(tmp_path), _spec()
    root = _producer_root(extended=True)
    assert _record(state, spec, _report(spec, root=root, roles=[]))["reason"] == "report_rejected"

    invalid_settings = {**root, "settings": []}
    malformed = _report(spec, root=invalid_settings, roles=[], login=None)
    assert _record(state, spec, malformed)["reason"] == "report_rejected"
    assert not _path(state, spec).exists()


@pytest.mark.parametrize("permissions", [
    [],
    {"supported": True, "network": "restricted", "reasons": []},
    {"supported": True, "network": "restricted", "entries": {}, "reasons": []},
    {"supported": True, "network": "restricted", "entries": ["entry"], "reasons": []},
    {"supported": True, "network": "restricted", "entries": [{}], "reasons": {}},
])
def test_root_permission_envelope_refuses_malformed_containers(tmp_path, permissions):
    state, spec = _state(tmp_path), _spec()
    root = _producer_root()
    accepted = _report(spec, root=root, roles=[], login=None)
    assert _record(state, spec, accepted)["reason"] == "receipt_recorded"
    before = _path(state, spec).read_bytes()

    root["observed_permissions"] = permissions
    malformed = _report(spec, root=root, roles=[], login=None)
    assert _record(state, spec, malformed, version_reader=_reader("9.9.9"))["reason"] == "report_rejected"
    assert _path(state, spec).read_bytes() == before


@pytest.mark.parametrize("tag", [None, False, 1])
def test_invalid_empty_receipt_cannot_be_read_or_replaced(tmp_path, tag):
    state, spec = _state(tmp_path), _spec()
    report = _report(spec, root=_producer_root(), roles=[], login=None)
    assert _record(state, spec, report)["reason"] == "receipt_recorded"
    path = _path(state, spec)
    body = json.loads(path.read_bytes())
    if tag is None:
        body.pop("root_only")
    else:
        body["root_only"] = tag
    raw = json.dumps(body).encode("utf-8")
    path.write_bytes(raw)
    assert qualify.status(str(state), spec.id, version_reader=_reader())["reason"] == "record_invalid"
    assert _record(state, spec, report, version_reader=_reader("9.9.9"))["reason"] == "record_invalid"
    assert path.read_bytes() == raw
