"""Wake port: measured legacy parity, fixed refusals and descriptor confinement."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timezone
import errno
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
from types import SimpleNamespace

import pytest

from conftest import symlink_or_skip
from aegis_core import team_session_wake as core
from aegis_core import team_mailbox as mail
from aegis_core import team_mailbox_store as storage
from aegis_core import team_host_registry as registry
from aegis_core.team_mailbox_primitives import MailboxRefusal, RoleTables
from aegis_core.storage_confined import ConfinedFileError
from aegis_core.workspace.layout import UserLayout
from tools import hierarchy_wake as legacy


NOW = datetime(2026, 11, 17, 12, tzinfo=timezone.utc)
TARGET = "a/orchestrator"
MANIFEST = {"schema": "aegis.hierarchy-pilot/v1", "endpoints": {
    "a/front-door": {}, TARGET: {}}, "counterparts": [], "writer_limit": 2}
ROLES = RoleTables(writes={"owner": {"initialize", "bind", "publish", "write_delivery_receipt", "record_read"}})
OPTIONS = dict(clock=lambda: NOW, roles=ROLES, hosts={"host-one": object()}, caller_role="owner")


@pytest.fixture(autouse=True)
def owner_plane(tmp_path, monkeypatch):
    layout = UserLayout(tmp_path / "owner")
    layout.aegis_dir.mkdir(parents=True, mode=0o700)
    monkeypatch.setattr(storage, "pwd", SimpleNamespace(
        getpwuid=lambda uid: SimpleNamespace(pw_dir=str(layout.home))))


def make_store(tmp_path):
    if not storage.descriptor_supported():
        pytest.skip("descriptor-relative no-follow storage required")
    root = tmp_path / "mailbox"
    mail.initialize(root, MANIFEST, roles=ROLES, caller_role="owner")
    with mail.Mailbox(root, **OPTIONS) as box:
        for endpoint in MANIFEST["endpoints"]:
            box.bind({"endpoint": endpoint, "host": "host-one", "session": endpoint,
                      "expected_generation": 0})
    return root


def profile(tmp_path, **changes):
    value = {"schema": legacy.PROFILE_SCHEMA, "endpoint": TARGET, "host": "host-one", "session": TARGET,
             "generation": 1, "argv": ["host", TARGET], "cwd": str(tmp_path), "timeout_seconds": 10,
             "prompt_via": "argv", **changes}
    path = tmp_path / "profile.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    return path, value


def snapshot(root):
    return {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}


def publish(root):
    with mail.Mailbox(root, **OPTIONS) as box:
        box.publish({"message_id": "note", "from": "a/front-door", "to": TARGET, "host": "host-one",
                     "session": "a/front-door", "binding_generation": 1, "type": "info", "body": "untrusted"})


def invoke(root, path, **ports):
    return core.wake(root, root.parent / "delivery", TARGET, path, mailbox_options=OPTIONS, **ports)


def claude_context(tmp_path, background=True):
    if not storage.descriptor_supported():
        pytest.skip("descriptor-relative no-follow storage required")
    entry = registry.entry(registry.CLAUDE)
    options = {**OPTIONS, "hosts": {registry.CLAUDE: entry}}
    root = tmp_path / "mailbox"
    mail.initialize(root, MANIFEST, roles=ROLES, caller_role="owner")
    with mail.Mailbox(root, **options) as box:
        for endpoint in MANIFEST["endpoints"]:
            box.bind({"endpoint": endpoint, "host": registry.CLAUDE, "session": endpoint,
                      "expected_generation": 0})
        box.publish({"message_id": "note", "from": "a/front-door", "to": TARGET, "host": registry.CLAUDE,
                     "session": "a/front-door", "binding_generation": 1, "type": "info", "body": "untrusted"})
    changes = {"host": registry.CLAUDE}
    if background:
        changes.update(mode="background", control=["host"])
    path, request = profile(tmp_path, **changes)
    return root, options, entry, path, request


@pytest.fixture
def local_owner(tmp_path, monkeypatch):
    if not storage.descriptor_supported():
        pytest.skip("descriptor-relative no-follow storage required")
    class OwnerPath(type(Path())):
        @classmethod
        def home(cls):
            return tmp_path
    monkeypatch.setattr(core, "Path", OwnerPath)
    monkeypatch.setattr(core, "os", SimpleNamespace(**{**vars(os), "kill": lambda pid, sig: None}))
    monkeypatch.setattr(core, "time", SimpleNamespace(**{**vars(time), "sleep": lambda pause: None}))
    monkeypatch.setattr(core, "process_names_session", lambda session: False)


def failed_receipt(box, directory, request, wake_id):
    base = {key: request[key] for key in ("endpoint", "host", "session", "generation")}
    def fail(reason, record=True):
        if record:
            box.write_delivery_receipt(directory, "wakes", {
                **base, "message_ids": ["note"], "wake_id": wake_id, "state": "failed_to_start",
                "exit_code": None, "timed_out": False})
        return 3, {"state": "failed_to_start", "error": reason}
    return fail


@pytest.mark.parametrize("changes", [{"schema": "bad"}, {"endpoint": "a/root"}, {"generation": 2},
    {"argv": []}, {"cwd": "/missing-wake-cwd"}, {"timeout_seconds": 0}, {"prompt_via": "bad"},
    {"mode": "bad"}, {"control": ["host"]}])
def test_measured_profile_refusals_are_atomic_and_retryable(tmp_path, changes):
    if not storage.descriptor_supported():
        pytest.skip("descriptor-relative no-follow storage required")
    path, good = profile(tmp_path)
    binding = {key: good[key] for key in ("host", "session", "generation")}
    path.write_text(json.dumps({**good, **changes}), encoding="utf-8")
    with pytest.raises(ValueError):
        legacy.load_profile(path, TARGET, binding)
    before = snapshot(tmp_path)
    with pytest.raises(core.WakeRefusal) as caught:
        core.load_profile(path, TARGET, binding)
    assert caught.value.code == 2
    assert caught.value.next_action
    assert snapshot(tmp_path) == before
    path.write_text(json.dumps(good), encoding="utf-8")
    assert core.load_profile(path, TARGET, binding) == legacy.load_profile(path, TARGET, binding)


@pytest.mark.parametrize("raw", ["{", "[]", '{"schema":NaN}'])
def test_malformed_profiles_have_fixed_diagnostics(tmp_path, raw):
    if not storage.descriptor_supported():
        pytest.skip("descriptor-relative no-follow storage required")
    path, good = profile(tmp_path)
    path.write_text(raw, encoding="utf-8")
    with pytest.raises(ValueError):
        legacy.load_profile(path, TARGET, good)
    with pytest.raises(core.WakeRefusal, match="^wake refused: invalid_record$"):
        core.load_profile(path, TARGET, good)


def test_unsupported_platform_is_typed(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "descriptor_supported", lambda: False)
    path, good = profile(tmp_path)
    assert legacy.load_profile(path, TARGET, good) == good
    with pytest.raises(core.WakeRefusal, match="^wake refused: unsupported_platform$"):
        core.load_profile(path, TARGET, good)
    with pytest.raises(core.WakeRefusal, match="^wake refused: unsupported_platform$"):
        core.claude_table_lists_session("session-one", home=tmp_path,
                                       host_entry=registry.entry(registry.CLAUDE))


def test_session_table_checks_platform_before_home_discovery(monkeypatch):
    def unexpected_home():
        raise AssertionError("unsupported session census must not discover a home path")
    monkeypatch.setattr(core, "descriptor_supported", lambda: False)
    monkeypatch.setattr(core, "Path", SimpleNamespace(home=unexpected_home))
    with pytest.raises(core.WakeRefusal, match="^wake refused: unsupported_platform$"):
        core.claude_table_lists_session("session-one", host_entry=registry.entry(registry.CLAUDE))


def test_dry_and_empty_wakes_match_pinned_source(tmp_path):
    root = make_store(tmp_path)
    path, _ = profile(tmp_path)
    before = snapshot(tmp_path)
    assert invoke(root, path) == legacy.wake(root, tmp_path / "delivery", TARGET, path)
    assert snapshot(tmp_path) == before
    publish(root)
    before = snapshot(tmp_path)
    assert invoke(root, path, dry_run=True) == legacy.wake(root, tmp_path / "delivery", TARGET, path, dry_run=True)
    assert snapshot(tmp_path) == before


def test_duplicate_claim_concurrent_and_retry(tmp_path):
    root = make_store(tmp_path)
    with mail.Mailbox(root, **OPTIONS) as box:
        def claim():
            try:
                return core.claim_wake(box, TARGET)
            except core.WakeRefusal as error:
                return error
        with ThreadPoolExecutor(max_workers=2) as workers:
            results = list(workers.map(lambda _: claim(), range(2)))
        refused = [item for item in results if isinstance(item, core.WakeRefusal)]
        assert len(refused) == 1 and refused[0].reason == "busy"
        with pytest.raises(ValueError, match="a wake is already in progress"):
            legacy.claim_wake(legacy.Mailbox(root), TARGET)
        marker = next(item for item in results if not isinstance(item, core.WakeRefusal))
        marker.unlink()
        core.claim_wake(box, TARGET).unlink()


def test_existing_marker_and_binding_mismatch_launch_nothing(tmp_path, monkeypatch):
    root = make_store(tmp_path)
    publish(root)
    path, good = profile(tmp_path)
    calls = []
    monkeypatch.setattr(core, "process_names_session", lambda session: calls.append(session) or False)
    with mail.Mailbox(root, **OPTIONS) as box:
        marker = core.claim_wake(box, TARGET)
        before = snapshot(tmp_path)
        code, result = invoke(root, path)
        assert code == 2 and result["reason"] == "busy" and calls == []
        assert snapshot(tmp_path) == before
        marker.unlink()
    path.write_text(json.dumps({**good, "generation": 2}), encoding="utf-8")
    before = snapshot(tmp_path)
    code, result = invoke(root, path)
    assert code == 2 and result["reason"] == "binding_mismatch"
    assert result["endpoint"] == TARGET and calls == []
    assert snapshot(tmp_path) == before


def test_missing_transcript_port_refuses_before_claim(tmp_path):
    if not storage.descriptor_supported():
        pytest.skip("descriptor-relative no-follow storage required")
    root = tmp_path / "mailbox"
    options = {**OPTIONS, "hosts": {"claude-code": object()}}
    mail.initialize(root, MANIFEST, roles=ROLES, caller_role="owner")
    with mail.Mailbox(root, **options) as box:
        for endpoint in MANIFEST["endpoints"]:
            box.bind({"endpoint": endpoint, "host": "claude-code", "session": endpoint,
                      "expected_generation": 0})
        box.publish({"message_id": "note", "from": "a/front-door", "to": TARGET, "host": "claude-code",
                     "session": "a/front-door", "binding_generation": 1, "type": "info", "body": "untrusted"})
    path, _ = profile(tmp_path, host="claude-code", mode="background", control=["host"])
    before = snapshot(tmp_path)
    code, result = core.wake(root, tmp_path / "delivery", TARGET, path, mailbox_options=options)
    assert code == 2 and result["reason"] == "transcript_unavailable"
    assert snapshot(tmp_path) == before
    with mail.Mailbox(root, **options) as box:
        binding = {"host": "claude-code", "session": TARGET, "generation": 1}
        parsed = core.load_profile(path, TARGET, binding)
        with pytest.raises(core.WakeRefusal, match="^wake refused: transcript_unavailable$"):
            core.transcript_mark(parsed)
        assert core.transcript_mark(parsed, find_transcript=lambda host, session: None) is None
        assert not box.store.exists(box.wake_marker(TARGET))


def test_transcript_port_parity_and_anchored_stat(tmp_path, monkeypatch):
    if not storage.descriptor_supported():
        pytest.skip("descriptor-relative no-follow storage required")
    path = tmp_path / "transcript.jsonl"
    path.write_text("record", encoding="utf-8")
    value = {"host": "host-one", "session": TARGET}
    monkeypatch.setattr(legacy, "find_transcript", lambda host, session: path)
    assert core.transcript_mark(value, find_transcript=lambda host, session: path) == legacy.transcript_mark(value)
    assert core.transcript_mark(value, find_transcript=lambda host, session: None) is None


def test_profile_symlink_and_oversize_refusal_parity(tmp_path):
    if not storage.descriptor_supported():
        pytest.skip("descriptor-relative no-follow storage required")
    path, good = profile(tmp_path)
    link = tmp_path / "linked.json"
    symlink_or_skip(path, link)
    with pytest.raises(core.WakeRefusal, match="^wake refused: unsafe_path$"):
        core.load_profile(link, TARGET, good)
    with pytest.raises(ValueError, match="symlink paths are not supported"):
        legacy.load_profile(link, TARGET, good)
    path.write_text(json.dumps({**good, "argv": ["x" * 270000, TARGET]}), encoding="utf-8")
    with pytest.raises(core.WakeRefusal, match="^wake refused: too_large$"):
        core.load_profile(path, TARGET, good)
    with pytest.raises(ValueError, match="input exceeds 262144 bytes"):
        legacy.load_profile(path, TARGET, good)


def test_claim_uses_held_root_after_rename(tmp_path):
    root = make_store(tmp_path)
    with mail.Mailbox(root, **OPTIONS) as box:
        moved = tmp_path / "moved"
        root.rename(moved)
        root.mkdir(mode=0o700)
        marker = core.claim_wake(box, TARGET)
        assert not list(root.iterdir())
        assert (moved / marker.name).is_file()
        marker.unlink()
        assert not (moved / marker.name).exists()


def test_launch_failure_is_fixed_recorded_and_retry_works(tmp_path, monkeypatch):
    root = make_store(tmp_path)
    publish(root)
    path, _ = profile(tmp_path)
    monkeypatch.setattr(core, "process_names_session", lambda session: False)
    def fail(*args, **kwargs):
        raise OSError(errno.ENOENT, "token=super-secret-input")
    monkeypatch.setattr(core, "start_turn", fail)
    code, result = invoke(root, path)
    assert code == 3 and result["state"] == "failed_to_start"
    assert result["error"] == "launch_failed" and "super-secret" not in json.dumps(result)
    with mail.Mailbox(root, **OPTIONS) as box:
        assert not box.store.exists(box.wake_marker(TARGET))
    assert list((tmp_path / "delivery" / "wakes").rglob("*.json"))
    assert invoke(root, path)[1]["state"] == "failed_to_start"


def test_log_open_failure_closes_first_descriptor(tmp_path, monkeypatch):
    if not storage.descriptor_supported():
        pytest.skip("descriptor-relative no-follow storage required")
    _, good = profile(tmp_path)
    opened = []
    real_open = os.open
    def fail_second(path, flags, *args, **kwargs):
        if str(path).endswith(".stderr"):
            raise OSError(errno.EACCES, "private")
        fd = real_open(path, flags, *args, **kwargs)
        if str(path).endswith(".stdout"):
            opened.append(fd)
        return fd
    monkeypatch.setattr(core, "os", SimpleNamespace(**{**vars(os), "open": fail_second}))
    with pytest.raises(core.WakeRefusal):
        core.start_turn(good, tmp_path / "logs", "wake-one", "prompt")
    assert len(opened) == 1
    with pytest.raises(OSError, match="Bad file descriptor"):
        os.fstat(opened[0])
    assert not (tmp_path / "logs" / "wake-one.stdout").exists()


def test_json_container_bound_is_explicit_compatibility_delta(tmp_path):
    if not storage.descriptor_supported():
        pytest.skip("descriptor-relative no-follow storage required")
    path, good = profile(tmp_path, argv=[TARGET] * 10001)
    assert legacy.load_profile(path, TARGET, good) == good
    with pytest.raises(core.WakeRefusal) as caught:
        core.load_profile(path, TARGET, good)
    assert caught.value.reason in {"too_large", "invalid_record"}


def test_process_capture_bound_is_measured_success_to_refusal(tmp_path, monkeypatch):
    payload = "1 unrelated\n" * 100000
    def run(argv, **options):
        if options.get("capture_output"):
            return subprocess.CompletedProcess(argv, 0, payload, "")
        options["stdout"].write(payload.encode("utf-8"))
        return subprocess.CompletedProcess(argv, 0)
    monkeypatch.setattr(core, "subprocess", SimpleNamespace(**{**vars(subprocess), "run": run}))
    monkeypatch.setattr(legacy, "subprocess", SimpleNamespace(**{**vars(subprocess), "run": run}))
    assert legacy.process_names_session("absent-session") is False
    with pytest.raises(core.WakeRefusal, match="^wake refused: too_large$"):
        core.process_names_session("absent-session")


@pytest.mark.parametrize("error,reason", [
    (OSError(errno.ENOENT, "private-command"), "missing"),
    (PermissionError(errno.EPERM, "private-command"), "io"),
    (subprocess.TimeoutExpired("private-command", 1), "control_failed"),
], ids=["missing", "io", "timeout"])
def test_process_census_failure_is_fixed_and_retryable(tmp_path, monkeypatch, error, reason):
    attempts = []
    def run(argv, **options):
        attempts.append(argv)
        if len(attempts) == 1:
            raise error
        options["stdout"].write(b"1 unrelated\n")
        return subprocess.CompletedProcess(argv, 0)
    monkeypatch.setattr(core, "subprocess", SimpleNamespace(**{**vars(subprocess), "run": run}))
    with pytest.raises(core.WakeRefusal, match="^wake refused: " + reason + "$") as caught:
        core.process_names_session("absent-session")
    assert caught.value.code == 2 and caught.value.next_action
    assert "private-command" not in json.dumps(caught.value.as_dict())
    assert core.process_names_session("absent-session") is False
    assert len(attempts) == 2


@pytest.mark.parametrize("custom_folder", [False, True])
def test_session_table_uses_injected_folder_and_retry(tmp_path, monkeypatch, custom_folder):
    if not storage.descriptor_supported():
        pytest.skip("descriptor-relative no-follow storage required")
    entry = registry.entry(registry.CLAUDE)
    if custom_folder:
        entry["home"]["owner_folder"] = "owner-runtime"
    folder = tmp_path / entry["home"]["owner_folder"] / "sessions"
    folder.mkdir(parents=True, mode=0o700)
    (folder / "one.json").write_text(json.dumps({"sessionId": "session-one", "pid": 42}), encoding="utf-8")
    live, calls = [False], []
    def kill(pid, sig):
        calls.append((pid, sig))
        if not live[0]:
            raise ProcessLookupError(errno.ESRCH, "private-process")
    monkeypatch.setattr(core, "os", SimpleNamespace(**{**vars(os), "kill": kill}))
    before = snapshot(tmp_path)
    assert core.claude_table_lists_session("session-one", home=tmp_path, host_entry=entry) is False
    live[0] = True
    assert core.claude_table_lists_session("session-one", home=tmp_path, host_entry=entry) is True
    assert calls == [(42, 0), (42, 0)] and snapshot(tmp_path) == before
    if not custom_folder:
        monkeypatch.setattr(legacy, "Path", SimpleNamespace(home=lambda: tmp_path))
        monkeypatch.setattr(legacy, "os", SimpleNamespace(**{**vars(os), "kill": kill}))
        assert legacy.claude_table_lists_session("session-one") is True


@pytest.mark.parametrize("entry,reason", [
    (None, "invalid_record"), ({}, "invalid_record"), ({"home": None}, "invalid_record"),
    ({"home": {}}, "invalid_record"), ({"home": {"owner_folder": []}}, "invalid_record"),
    ({"home": {"owner_folder": "../escape"}}, "unsafe_path"),
    ({"home": {"owner_folder": "/escape"}}, "unsafe_path"),
    ({"home": {"owner_folder": ".."}}, "unsafe_path"),
    ({"home": {"owner_folder": "."}}, "unsafe_path"),
    ({"home": {"owner_folder": "nested/path"}}, "unsafe_path"),
    ({"home": {"owner_folder": "nested\\path"}}, "unsafe_path"),
    ({"home": {"owner_folder": "x" * 256}}, "invalid_record"),
    ({"home": {"owner_folder": "é" * 128}}, "unsafe_path"),
    ({"home": {"owner_folder": "bad\x00folder"}}, "invalid_record"),
    ({"home": {"owner_folder": "\ud800"}}, "invalid_record"),
])
def test_invalid_session_folder_refuses_without_effect_and_retries(tmp_path, entry, reason):
    if not storage.descriptor_supported():
        pytest.skip("descriptor-relative no-follow storage required")
    before = snapshot(tmp_path)
    with pytest.raises(core.WakeRefusal, match="^wake refused: " + reason + "$"):
        core.claude_table_lists_session("session-one", home=tmp_path, host_entry=entry)
    assert snapshot(tmp_path) == before
    assert core.claude_table_lists_session("session-one", home=tmp_path,
                                         host_entry=registry.entry(registry.CLAUDE)) is False
    assert snapshot(tmp_path) == before


def test_session_folder_read_keeps_descriptor_across_ancestor_rename(tmp_path, monkeypatch):
    if not storage.descriptor_supported():
        pytest.skip("descriptor-relative no-follow storage required")
    entry = registry.entry(registry.CLAUDE)
    owner = tmp_path / entry["home"]["owner_folder"]
    (owner / "sessions").mkdir(parents=True, mode=0o700)
    (owner / "sessions" / "one.json").write_text(
        json.dumps({"sessionId": "session-one", "pid": 42}), encoding="utf-8")
    outside = tmp_path / "outside"
    (outside / "sessions").mkdir(parents=True, mode=0o700)
    (outside / "sessions" / "one.json").write_text(
        json.dumps({"sessionId": "session-one", "pid": 43}), encoding="utf-8")
    confined = core.confined_file
    @contextmanager
    def renamed(root, parts, create_parents=False):
        with confined(root, parts, create_parents=create_parents) as handle:
            owner.rename(tmp_path / "held-owner")
            symlink_or_skip(outside, owner, target_is_directory=True)
            yield handle
    observed = []
    monkeypatch.setattr(core, "confined_file", renamed)
    monkeypatch.setattr(core, "os", SimpleNamespace(**{**vars(os), "kill": lambda pid, sig: observed.append(pid)}))
    assert core.claude_table_lists_session("session-one", home=tmp_path, host_entry=entry) is True
    assert observed == [42]
    with pytest.raises(core.WakeRefusal, match="^wake refused: unsafe_path$"):
        core.claude_table_lists_session("session-one", home=tmp_path, host_entry=entry)
    assert observed == [42]


def test_failed_launch_settlement_receives_injected_session_folder(tmp_path, monkeypatch):
    if not storage.descriptor_supported():
        pytest.skip("descriptor-relative no-follow storage required")
    entry = registry.entry(registry.CLAUDE)
    entry["home"]["owner_folder"] = "owner-runtime"
    folder = tmp_path / entry["home"]["owner_folder"] / "sessions"
    folder.mkdir(parents=True, mode=0o700)
    (folder / "one.json").write_text(json.dumps({"sessionId": "session-one", "pid": 42}), encoding="utf-8")
    class OwnerPath(type(Path())):
        @classmethod
        def home(cls):
            return tmp_path
    live = [True]
    def kill(pid, sig):
        if not live[0]:
            raise ProcessLookupError(errno.ESRCH, "private-process")
    monkeypatch.setattr(core, "Path", OwnerPath)
    monkeypatch.setattr(core, "os", SimpleNamespace(**{**vars(os), "kill": kill}))
    monkeypatch.setattr(core, "process_names_session", lambda session: False)
    monkeypatch.setattr(core, "control_command", lambda *args: subprocess.CompletedProcess([], 0, "[]"))
    request = {"host": registry.CLAUDE, "session": "session-one"}
    before = snapshot(tmp_path)
    assert core.settle_failed_launch(request, False, host_entry=entry) == (None, False)
    live[0] = False
    assert core.settle_failed_launch(request, False, host_entry=entry) == (None, True)
    assert snapshot(tmp_path) == before


def test_wake_uses_injected_session_folder_before_launch_and_on_retry(tmp_path, monkeypatch):
    if not storage.descriptor_supported():
        pytest.skip("descriptor-relative no-follow storage required")
    entry = registry.entry(registry.CLAUDE)
    entry["home"]["owner_folder"] = "owner-runtime"
    options = {**OPTIONS, "hosts": {registry.CLAUDE: entry}}
    root = tmp_path / "mailbox"
    mail.initialize(root, MANIFEST, roles=ROLES, caller_role="owner")
    with mail.Mailbox(root, **options) as box:
        for endpoint in MANIFEST["endpoints"]:
            box.bind({"endpoint": endpoint, "host": registry.CLAUDE, "session": endpoint,
                      "expected_generation": 0})
        box.publish({"message_id": "note", "from": "a/front-door", "to": TARGET, "host": registry.CLAUDE,
                     "session": "a/front-door", "binding_generation": 1, "type": "info", "body": "untrusted"})
    path, _ = profile(tmp_path, host=registry.CLAUDE)
    folder = tmp_path / entry["home"]["owner_folder"] / "sessions"
    folder.mkdir(parents=True, mode=0o700)
    (folder / "one.json").write_text(json.dumps({"sessionId": TARGET, "pid": 42}), encoding="utf-8")
    class OwnerPath(type(Path())):
        @classmethod
        def home(cls):
            return tmp_path
    live, launched = [True], []
    def kill(pid, sig):
        if not live[0]:
            raise ProcessLookupError(errno.ESRCH, "private-process")
    def popen(*args, **kwargs):
        child = StubProcess()
        launched.append(child)
        return child
    monkeypatch.setattr(core, "Path", OwnerPath)
    monkeypatch.setattr(core, "process_names_session", lambda session: False)
    monkeypatch.setattr(core, "os", SimpleNamespace(**{**vars(os), "kill": kill}))
    monkeypatch.setattr(core, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": popen}))
    monkeypatch.setattr(core, "stop_group", lambda process: None)
    before = snapshot(tmp_path)
    def wake_once():
        return core.wake(root, tmp_path / "delivery", TARGET, path, mailbox_options=options)
    entry["home"]["owner_folder"] = "../escape"
    code, result = wake_once()
    assert code == 2 and result["reason"] == "unsafe_path"
    assert snapshot(tmp_path) == before and launched == []
    entry["home"]["owner_folder"] = "owner-runtime"
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: wake_once(), range(2)))
    assert all(code == 2 and result["reason"] == "session_running" for code, result in results)
    assert launched == [] and snapshot(tmp_path) == before
    live[0] = False
    assert wake_once()[1]["state"] == "woken_unread"
    assert len(launched) == 1 and not list(root.glob(".wake-*"))


def test_generation_and_argv_validation_preserve_legacy_profile_successes(tmp_path):
    if not storage.descriptor_supported():
        pytest.skip("descriptor-relative no-follow storage required")
    path, good = profile(tmp_path, generation=True, argv=["host\x00", TARGET])
    assert core.load_profile(path, TARGET, good) == legacy.load_profile(path, TARGET, good)


class StubProcess:
    def __init__(self, *, timeout=False):
        self.pid, self.returncode, self.stdin = 123456, 0, None
        self.timeout, self.waited, self.communications = timeout, False, []

    def communicate(self, **options):
        self.communications.append(options)
        if self.timeout:
            raise subprocess.TimeoutExpired("private-command", 1)

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        self.waited = True
        return self.returncode


@pytest.mark.parametrize("via", ["argv", "stdin"])
def test_success_launch_releases_writer_before_child_and_preserves_parity(tmp_path, monkeypatch, via):
    root = make_store(tmp_path)
    publish(root)
    path, good = profile(tmp_path, prompt_via=via)
    observed, stopped = [], []
    child = StubProcess()
    def popen(argv, **options):
        with mail.Mailbox(root, **OPTIONS) as box:
            with box.store.lock(root):
                observed.append((argv, options))
        return child
    monkeypatch.setattr(core, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": popen}))
    monkeypatch.setattr(core, "process_names_session", lambda session: False)
    monkeypatch.setattr(core, "stop_group", lambda process: stopped.append(process))
    code, result = invoke(root, path)
    assert code == 3 and result["state"] == "woken_unread"
    assert result["still_unread"] == ["note"] and result["read"] == []
    assert stopped == [child]
    argv, options = observed[0]
    assert argv[:2] == good["argv"]
    assert argv == good["argv"] if via == "stdin" else argv[-1] == legacy.wake_prompt(legacy.Mailbox(root), TARGET)
    assert options["start_new_session"] is True
    assert child.communications[0]["input"] == (legacy.wake_prompt(legacy.Mailbox(root), TARGET).encode()
                                                     if via == "stdin" else None)
    with mail.Mailbox(root, **OPTIONS) as box:
        assert not box.store.exists(box.wake_marker(TARGET))


@pytest.mark.parametrize("timeout", [False, True])
def test_finish_turn_stops_group_on_success_and_timeout(tmp_path, monkeypatch, timeout):
    child, stopped = StubProcess(timeout=timeout), []
    monkeypatch.setattr(core, "stop_group", lambda process: stopped.append(process))
    assert core.finish_turn(child, {"prompt_via": "stdin", "timeout_seconds": 1}, "prompt") == (0, timeout)
    assert stopped == [child]


def test_failure_recording_start_stops_child_and_releases_marker(tmp_path, monkeypatch):
    root = make_store(tmp_path)
    publish(root)
    path, _ = profile(tmp_path)
    child, stopped = StubProcess(), []
    real_mailbox = mail.Mailbox
    class FailingMailbox(real_mailbox):
        def write_delivery_receipt(self, *args):
            raise OSError(errno.ENOSPC, "token=private")
    monkeypatch.setattr(core, "Mailbox", FailingMailbox)
    monkeypatch.setattr(core, "process_names_session", lambda session: False)
    monkeypatch.setattr(core, "start_turn", lambda *args: (child, {"stdout": "out", "stderr": "err"}))
    monkeypatch.setattr(core, "stop_group", lambda process: stopped.append(process))
    code, result = invoke(root, path)
    assert code == 3 and result["error"] == "launch_failed" and stopped == [child]
    assert not list(root.glob(".wake-*"))


def test_control_output_refusals_and_retry_match_legacy(tmp_path, monkeypatch):
    values = iter(["not-json", "[]"])
    monkeypatch.setattr(core, "control_command", lambda *args: subprocess.CompletedProcess([], 0, next(values)))
    with pytest.raises(core.WakeRefusal, match="^wake refused: control_failed$"):
        core.background_entry({"session": TARGET})
    assert core.background_entry({"session": TARGET}) is None
    monkeypatch.setattr(legacy, "control_command", lambda *args: subprocess.CompletedProcess([], 0, "not-json"))
    with pytest.raises(ValueError, match="background session list is not JSON"):
        legacy.background_entry({"session": TARGET})


def test_log_output_canonicalizes_redacts_then_truncates(tmp_path, monkeypatch):
    if not storage.descriptor_supported():
        pytest.skip("descriptor-relative no-follow storage required")
    path = tmp_path / "stdout"
    path.write_text("", encoding="utf-8")
    shown = "\x1b[31mtoken=top-secret\x1b[0m Do you want to proceed?"
    monkeypatch.setattr(core, "control_command", lambda *args: subprocess.CompletedProcess([], 0, shown))
    assert core.save_terminal_output({}, {"id": "agent-one"}, {"stdout": str(path)}) is True
    output = path.read_text(encoding="utf-8")
    assert "top-secret" not in output and "\x1b" not in output
    old_path = tmp_path / "legacy-stdout"
    old_path.write_text("", encoding="utf-8")
    monkeypatch.setattr(legacy, "control_command", lambda *args: subprocess.CompletedProcess([], 0, shown))
    assert legacy.save_terminal_output({}, {"id": "agent-one"}, {"stdout": str(old_path)}) is True
    assert "top-secret" in old_path.read_text(encoding="utf-8")


def test_background_launch_timeout_settles_possible_late_session(tmp_path, monkeypatch):
    root = make_store(tmp_path)
    child, stopped, settled = StubProcess(timeout=True), [], []
    monkeypatch.setattr(core, "start_turn", lambda *args: (child, {}))
    monkeypatch.setattr(core, "stop_group", lambda process: stopped.append(process))
    def settle(profile, may_exist, *, host_entry=None):
        assert host_entry is OPTIONS["hosts"]["host-one"]
        settled.append(may_exist)
        return None, True
    monkeypatch.setattr(core, "settle_failed_launch", settle)
    with mail.Mailbox(root, **OPTIONS) as box:
        marker = core.claim_wake(box, TARGET)
        failure, _ = core.launch_background(box, tmp_path / "delivery", {"host": "host-one"}, {}, "wake-one", marker,
            tmp_path / "logs", {"message_ids": []}, lambda reason, record=True: (3, {"error": reason}), "prompt")
    assert failure[0] == 3 and settled == [True] and stopped == [child]


def test_background_success_keeps_the_background_turn_running(tmp_path, monkeypatch):
    child, stopped = StubProcess(), []
    monkeypatch.setattr(core, "start_turn", lambda *args: (child, {}))
    monkeypatch.setattr(core, "stop_group", lambda process: stopped.append(process))
    assert core.start_background({}, tmp_path, "wake-one", "prompt") == (0, {})
    assert stopped == []


def test_background_communication_io_error_keeps_unknown_launch_outcome(tmp_path, monkeypatch):
    class FaultProcess(StubProcess):
        def communicate(self, **options):
            raise OSError(errno.EIO, "private-process")
    child, stopped = FaultProcess(), []
    monkeypatch.setattr(core, "start_turn", lambda *args: (child, {}))
    monkeypatch.setattr(core, "stop_group", lambda process: stopped.append(process))
    with pytest.raises(core.WakeRefusal, match="^wake refused: launch_unknown$"):
        core.start_background({}, tmp_path, "wake-one", "prompt")
    assert stopped == [child]


def test_background_unconfirmed_group_retains_marker(tmp_path, monkeypatch):
    root = make_store(tmp_path)
    child = StubProcess(timeout=True)
    monkeypatch.setattr(core, "start_turn", lambda *args: (child, {}))
    def cannot_stop(process):
        raise OSError(errno.EPERM, "private-process")
    monkeypatch.setattr(core, "stop_group", cannot_stop)
    monkeypatch.setattr(core, "BACKGROUND_STOP_SECONDS", 0)
    listed = json.dumps([{"sessionId": TARGET, "id": "agent-one", "status": "busy", "kind": "background"}])
    monkeypatch.setattr(core, "control_command", lambda *args: subprocess.CompletedProcess([], 0, listed))
    with mail.Mailbox(root, **OPTIONS) as box:
        marker = core.claim_wake(box, TARGET)
        failure, _ = core.launch_background(box, tmp_path / "delivery", {"session": TARGET}, {}, "wake-one", marker,
            tmp_path / "logs", {"message_ids": []}, lambda reason, record=True: (3, {"error": reason}), "prompt")
        assert failure[0] == 3 and failure[1]["reason"] == "stop_unconfirmed"
        assert box.store.exists(box.wake_marker(TARGET))
        marker.unlink()


@pytest.mark.parametrize("signal_failure", [False, True])
def test_stop_group_reaps_or_returns_fixed_refusal(tmp_path, monkeypatch, signal_failure):
    if os.name != "posix":
        pytest.skip("POSIX process groups required")
    child = StubProcess()
    def killpg(pid, sig):
        if signal_failure:
            raise PermissionError(errno.EPERM, "private-process")
        raise ProcessLookupError(errno.ESRCH, "gone")
    monkeypatch.setattr(core, "os", SimpleNamespace(**{**vars(os), "killpg": killpg}))
    if signal_failure:
        with pytest.raises(core.WakeRefusal, match="^wake refused: io$"):
            core.stop_group(child)
        assert not child.waited
    else:
        assert core.stop_group(child) is None and child.waited


def test_runtime_verification_port_precedes_host_effects(tmp_path):
    root = make_store(tmp_path)
    path, _ = profile(tmp_path)
    (tmp_path / "provision.json").write_text("{}", encoding="utf-8")
    before = snapshot(tmp_path)
    code, result = invoke(root, path)
    assert code == 2 and result["reason"] == "runtime_source_unavailable"
    assert snapshot(tmp_path) == before
    observed = []
    assert invoke(root, path, runtime_verify=lambda value, parent: observed.append((value, parent)))[0] == 0
    assert observed == [({}, tmp_path)]


def test_pinned_source_bytes():
    path = Path(__file__).resolve().parents[3] / "tools" / "hierarchy_wake.py"
    assert hashlib.sha256(path.read_bytes()).hexdigest() == "cd5586fb0799c18b217b255fd3cbc455ff98ed2cfff7bb6b7fc813232f569668"


@pytest.mark.parametrize("entry", [{"status": "busy"}, {"status": "idle"}, {"status": "unknown"},
                                      {"status": "busy", "waitingFor": "owner"}])
def test_host_state_parity(entry):
    assert core.look_of(entry) == legacy.look_of(entry)


@pytest.mark.parametrize("kind,reason", [("bytes", "too_large"), ("items", "invalid_record"),
    ("depth", "invalid_record"), ("json", "invalid_record"), ("shape", "invalid_record"),
    ("pid", "invalid_record")])
def test_unread_session_records_never_establish_absence(tmp_path, monkeypatch, local_owner, kind, reason):
    root, options, entry, path, request = claude_context(tmp_path, background=False)
    folder = tmp_path / entry["home"]["owner_folder"] / "sessions"
    folder.mkdir(parents=True, mode=0o700)
    record = {"sessionId": TARGET, "pid": 42}
    if kind == "bytes":
        record["extra"] = "x" * core.MAX_BYTES
    elif kind == "items":
        record["extra"] = [0] * 10001
    elif kind == "depth":
        nested = 0
        for _ in range(40):
            nested = [nested]
        record["extra"] = nested
    elif kind == "pid":
        record["pid"] = "not-a-pid"
    raw = "{" if kind == "json" else json.dumps([] if kind == "shape" else record)
    stored = folder / "one.json"
    stored.write_text(raw, encoding="utf-8")
    if kind == "bytes":
        assert len(raw) > core.MAX_BYTES
        monkeypatch.setattr(legacy, "Path", SimpleNamespace(home=lambda: tmp_path))
        monkeypatch.setattr(legacy, "os", SimpleNamespace(**{**vars(os), "kill": lambda pid, sig: None}))
        assert legacy.claude_table_lists_session(TARGET) is True
    before = snapshot(tmp_path)
    with pytest.raises(core.WakeRefusal, match="^wake refused: " + reason + "$"):
        core.claude_table_lists_session(TARGET, host_entry=entry)
    def forbidden_launch(*args, **kwargs):
        raise AssertionError("uncertain session liveness must not launch")
    monkeypatch.setattr(core, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": forbidden_launch}))
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: core.wake(root, tmp_path / "delivery", TARGET, path,
                                                  mailbox_options=options), range(2)))
    assert all(code == 2 and result["reason"] == reason for code, result in results)
    assert snapshot(tmp_path) == before
    monkeypatch.setattr(core, "start_turn", lambda *args: (StubProcess(timeout=True), {}))
    monkeypatch.setattr(core, "stop_group", lambda process: None)
    monkeypatch.setattr(core, "control_command", lambda *args: subprocess.CompletedProcess([], 0, "[]"))
    monkeypatch.setattr(core, "BACKGROUND_START_SECONDS", 0)
    with mail.Mailbox(root, **options) as box:
        marker = core.claim_wake(box, TARGET)
        with pytest.raises(core.WakeRefusal, match="^wake refused: " + reason + "$"):
            core.launch_background(box, tmp_path / "delivery", request, {}, "wake-one", marker,
                tmp_path / "logs", {"message_ids": ["note"]},
                failed_receipt(box, tmp_path / "delivery", request, "wake-one"), "prompt")
        assert box.store.exists(box.wake_marker(TARGET))
        receipts = list((tmp_path / "delivery").rglob("*.json"))
        assert len(receipts) == 1 and json.loads(receipts[0].read_text())["state"] == "failed_to_start"
        stored.write_text(json.dumps({"sessionId": TARGET, "pid": 42}), encoding="utf-8")
        assert core.claude_table_lists_session(TARGET, host_entry=entry) is True
        marker.unlink()


def test_disappearing_session_record_is_not_a_missing_directory(tmp_path, monkeypatch, local_owner):
    entry = registry.entry(registry.CLAUDE)
    folder = tmp_path / entry["home"]["owner_folder"] / "sessions"
    folder.mkdir(parents=True, mode=0o700)
    path = folder / "one.json"
    path.write_text(json.dumps({"sessionId": TARGET, "pid": 42}), encoding="utf-8")
    original = core.ConfinedFile
    class VanishedFile(original):
        def read_bytes(self, limit):
            path.unlink()
            return super().read_bytes(limit)
    monkeypatch.setattr(core, "ConfinedFile", VanishedFile)
    with pytest.raises(core.WakeRefusal, match="^wake refused: missing$"):
        core.claude_table_lists_session(TARGET, host_entry=entry)


def test_background_mark_ignores_idle_cleanup_transcript_progress(tmp_path, monkeypatch, local_owner):
    root, options, entry, path, request = claude_context(tmp_path)
    transcript = tmp_path / "transcript.jsonl"
    transcript.write_text("before", encoding="utf-8")
    events, stopped, old_gone, started, looks = [], [], [False], [False], [0]
    def control(profile, *words):
        if words[0] == "stop":
            stopped.append(words[1])
            old_gone[0] = True
            transcript.write_text("old idle stop completed", encoding="utf-8")
            events.append("old-stop")
            rows = []
        elif not old_gone[0]:
            rows = [{"sessionId": TARGET, "id": "old-agent", "status": "idle", "kind": "background"}]
        elif not started[0]:
            rows = []
        else:
            looks[0] += 1
            rows = ([{"sessionId": TARGET, "id": "new-agent", "status": "idle" if looks[0] <= 3 else "busy",
                      "kind": "background"}] if looks[0] <= 4 else [])
        return subprocess.CompletedProcess([], 0, json.dumps(rows))
    class Launcher(StubProcess):
        def communicate(self, **options):
            started[0] = True
            events.append("new-start")
    def transcript_port(host, session):
        events.append("mark")
        return transcript
    monkeypatch.setattr(core, "control_command", control)
    monkeypatch.setattr(core, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": lambda *a, **k: Launcher()}))
    code, result = core.wake(root, tmp_path / "delivery", TARGET, path,
                             mailbox_options=options, find_transcript=transcript_port)
    assert code == 3 and result["background"]["ended"] == "exited"
    assert stopped == ["old-agent"]
    assert events.index("old-stop") < events.index("mark") < events.index("new-start")
    assert not list(root.glob(".wake-*"))


@pytest.mark.parametrize("host_stops,census_gone", [(False, False), (True, False), (True, True)])
def test_unconfirmed_launcher_group_is_settled_and_recorded(tmp_path, monkeypatch, local_owner,
                                                         host_stops, census_gone):
    root, options, entry, path, request = claude_context(tmp_path)
    live, commands = [True], []
    def control(profile, *words):
        commands.append(words[0])
        if words[0] == "stop" and host_stops:
            live[0] = False
        rows = [{"sessionId": TARGET, "id": "agent-one", "status": "busy", "kind": "background"}] if live[0] else []
        return subprocess.CompletedProcess([], 0, json.dumps(rows))
    def denied_stop(process):
        raise PermissionError(errno.EPERM, "private-group")
    monkeypatch.setattr(core, "control_command", control)
    monkeypatch.setattr(core, "BACKGROUND_STOP_SECONDS", 15 if host_stops else 0)
    monkeypatch.setattr(core, "process_names_session", lambda session: not census_gone)
    monkeypatch.setattr(core, "start_turn", lambda *args: (StubProcess(timeout=True), {}))
    monkeypatch.setattr(core, "stop_group", denied_stop)
    with mail.Mailbox(root, **options) as box:
        marker = core.claim_wake(box, TARGET)
        failure, _ = core.launch_background(box, tmp_path / "delivery", request, {}, "wake-one", marker,
            tmp_path / "logs", {"message_ids": ["note"]},
            failed_receipt(box, tmp_path / "delivery", request, "wake-one"), "prompt")
        confirmed = host_stops and census_gone
        assert failure[0] == 3 and "stop" in commands
        assert failure[1]["state"] == ("failed_to_start" if confirmed else "stop_unconfirmed")
        assert box.store.exists(box.wake_marker(TARGET)) is (not confirmed)
        receipts = list((tmp_path / "delivery").rglob("*.json"))
        assert len(receipts) == 1 and json.loads(receipts[0].read_text())["state"] == "failed_to_start"
        if not confirmed:
            marker.unlink()


@pytest.mark.parametrize("payload,operation,reason,action", [
    ([{"status": "busy"}], "idle", "session_running", "Wait for the bound session to stop before another wake."),
    ([{"status": "waiting", "waitingFor": "owner"}], "idle", "session_running", "Wait for the bound session to stop before another wake."),
    ([{"status": "unknown"}], "idle", "session_running", "Wait for the bound session to stop before another wake."),
    ([{"status": "idle", "kind": "interactive"}], "idle", "session_running", "Wait for the bound session to stop before another wake."),
    ([{"status": "idle"}], "idle", "stop_unconfirmed", "Inspect the process group; retain the wake lock until stopped."),
    ("{", "entry", "control_failed", "Inspect host control availability and retry after reconciliation."),
    ({}, "entry", "control_failed", "Inspect host control availability and retry after reconciliation."),
    ([{}, {}], "entry", "control_failed", "Inspect host control availability and retry after reconciliation."),
    ([{"id": None}], "entry", "control_failed", "Inspect host control availability and retry after reconciliation."),
    ([{"id": "-bad"}], "entry", "control_failed", "Inspect host control availability and retry after reconciliation."),
])
def test_host_control_refusal_reason_and_action(monkeypatch, payload, operation, reason, action):
    rows = ([{"sessionId": TARGET, "id": "agent-one", "status": "idle", "kind": "background", **row}
             for row in payload] if type(payload) is list else payload)
    shown = payload if type(payload) is str else json.dumps(rows)
    monkeypatch.setattr(core, "control_command", lambda *args: subprocess.CompletedProcess([], 0, shown))
    monkeypatch.setattr(core, "BACKGROUND_STOP_SECONDS", 0)
    with pytest.raises(core.WakeRefusal) as caught:
        core.clear_idle({"session": TARGET}) if operation == "idle" else core.background_entry({"session": TARGET})
    assert caught.value.as_dict() == {"status": "refused", "reason": reason, "next_action": action, "code": 2}


@pytest.mark.parametrize("family,reason,action", [
    ("mailbox", "unauthorized", "Use a caller role admitted for this operation."),
    ("mailbox", "exists", "Read the current history before retrying with a new identifier."),
    ("mailbox", "closed", "Open a new mailbox context."),
    ("confined", "invalid_path", "Supply an absolute confined path with bounded, valid components."),
    ("confined", "invalid_limit", "Supply a valid bounded storage byte limit."),
    ("confined", "invalid_data", "Supply bounded bytes to the storage operation."),
    ("confined", "invalid_mode", "Supply a valid private file mode."),
    ("confined", "durability", "Reconcile stored evidence after the durability failure before retrying."),
])
def test_storage_refusal_preserves_reason_and_action(monkeypatch, family, reason, action):
    error = MailboxRefusal(reason) if family == "mailbox" else ConfinedFileError(reason)
    def fail(*args, **kwargs):
        raise error
    monkeypatch.setattr(core, "subprocess", SimpleNamespace(**{**vars(subprocess), "run": fail}))
    with pytest.raises(core.WakeRefusal) as caught:
        core.control_command({"control": ["host"]}, "agents", "--json")
    assert caught.value.as_dict() == {"status": "refused", "reason": reason, "next_action": action, "code": 2}


@pytest.mark.parametrize("case,reason,action", [
    ("host", "unknown_host", "Select a host in the injected host table."),
    ("role", "unauthorized", "Use a caller role admitted for this operation."),
    ("runtime", "runtime_check_failed", "Restore the qualified runtime source and verify its identity before retrying."),
])
def test_wake_configuration_refusal_reason_and_action(tmp_path, case, reason, action):
    root = make_store(tmp_path)
    path, _ = profile(tmp_path)
    options, verify = dict(OPTIONS), None
    if case == "host":
        options["hosts"] = {"other-host": object()}
    elif case == "role":
        publish(root)
        options["roles"] = RoleTables(writes={"owner": set()})
    else:
        (tmp_path / "provision.json").write_text("{}", encoding="utf-8")
        def bad_runtime(value, parent):
            raise ValueError("private-runtime-identity")
        verify = bad_runtime
    before = snapshot(tmp_path)
    code, result = core.wake(root, tmp_path / "delivery", TARGET, path,
                             mailbox_options=options, runtime_verify=verify)
    assert code == 2 and result == {"status": "refused", "reason": reason, "next_action": action, "code": 2}
    assert snapshot(tmp_path) == before


def test_unrecognized_refusal_is_not_a_record_schema_failure():
    error = core.WakeRefusal("private-unregistered-reason")
    assert error.reason == "unexpected_failure"
    assert error.next_action == "Report the unrecognized wake refusal to the owner before retrying."
    assert "private-unregistered-reason" not in json.dumps(error.as_dict())


def test_transcript_port_failure_has_its_own_refusal_and_retry():
    def failed_port(host, session):
        raise ValueError("private-transcript-error")
    with pytest.raises(core.WakeRefusal) as caught:
        core.transcript_mark({"host": registry.CLAUDE, "session": TARGET}, find_transcript=failed_port)
    assert caught.value.reason == "transcript_failed"
    assert caught.value.next_action == "Restore the transcript observation port before retrying."
    assert core.transcript_mark({"host": registry.CLAUDE, "session": TARGET},
                                find_transcript=lambda host, session: None) is None


def test_non_utf8_control_response_is_control_failure(monkeypatch):
    def run(argv, **options):
        options["stdout"].write(b"\xff")
        return subprocess.CompletedProcess(argv, 0)
    monkeypatch.setattr(core, "subprocess", SimpleNamespace(**{**vars(subprocess), "run": run}))
    with pytest.raises(core.WakeRefusal) as caught:
        core.background_entry({"control": ["host"], "session": TARGET})
    assert caught.value.reason == "control_failed"
    assert caught.value.next_action == "Inspect host control availability and retry after reconciliation."
