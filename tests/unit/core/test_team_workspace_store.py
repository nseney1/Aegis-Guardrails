"""Public workspace contracts, with the legacy implementation as a test oracle."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import ast
import errno
import hashlib
import inspect
import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from threading import Event, local
from types import SimpleNamespace

import pytest

from conftest import symlink_or_skip
from aegis_core import team_mailbox_store as storage
from aegis_core import team_workspace_store as workspace
from aegis_core import team_workspace_display as display
from aegis_core.team_workspace_display import WorkspaceRefusal
from aegis_core.team_mailbox_primitives import validate_warnings
from tools import hierarchy_workspace as legacy
from tests.unit.core.test_team_workspace_display import credential_positions


NOW = "2026-11-17T14:00:00.000000Z"
LIMITS = {"writer_limit": 5, "heavy_limit": 3, "heavy_tests_limit": 1}
INITIATIVE = {"id": "alpha", "project": "project", "repository": "repo", "priority": 1,
              "target_branch": "main"}


def stat_observation(info, mode, uid):
    return SimpleNamespace(st_dev=info.st_dev, st_ino=info.st_ino, st_mode=mode, st_uid=uid,
                           st_size=info.st_size, st_mtime_ns=info.st_mtime_ns, st_ctime_ns=info.st_ctime_ns,
                           st_nlink=info.st_nlink)


@pytest.fixture(autouse=True)
def trusted_test_ancestors(monkeypatch):
    """Model a private test root without changing shared host directory modes.

    The sandbox remaps root ownership and exposes a group-writable owner ancestor.
    Model known fixture ancestry as UID-0/private at this module's OS boundary;
    policy tests separately inject each trusted and untrusted mode/owner.
    """
    if os.name != "posix":
        return
    ancestors, root_owned = set(), set()
    root_uid = Path(Path.cwd().anchor).stat().st_uid
    for path in Path.cwd().parents:
        info = path.stat()
        if info.st_uid == os.geteuid() and info.st_mode & 0o020 and not info.st_mode & 0o002:
            ancestors.add((info.st_dev, info.st_ino))
        if info.st_uid == root_uid and info.st_uid != os.geteuid():
            root_owned.add((info.st_dev, info.st_ino))
    real_fstat = os.fstat
    def fixture_info(fd):
        info = real_fstat(fd)
        identity = info.st_dev, info.st_ino
        if identity in ancestors or identity in root_owned:
            return stat_observation(info, info.st_mode & ~0o020 if identity in ancestors else info.st_mode,
                                    0 if identity in root_owned else info.st_uid)
        return info
    monkeypatch.setattr(workspace, "os", SimpleNamespace(**{**vars(os), "fstat": fixture_info}))


def _public_entries():
    """Discover definitions and class methods; no hand-kept API example list."""
    cases = []
    for module in (workspace, display):
        for name, entry in inspect.getmembers(module):
            if name.startswith("_") or not (inspect.isfunction(entry) or inspect.isclass(entry)):
                continue
            if entry.__module__ != module.__name__:
                continue
            cases.append(pytest.param(None, entry, id=module.__name__ + "." + name))
            if inspect.isclass(entry):
                for method_name, method in inspect.getmembers(entry, inspect.isfunction):
                    if not method_name.startswith("_") and method.__module__ == module.__name__:
                        cases.append(pytest.param(entry, method,
                            id=module.__name__ + "." + name + "." + method_name))
    return cases


@pytest.mark.parametrize("owner,entry", _public_entries())
def test_generated_wrong_type_over_every_public_entrypoint(tmp_path, owner, entry):
    receiver = None
    if owner is workspace.WorkspaceStore:
        receiver = owner(make_store(tmp_path))
    elif owner is workspace.Ledger:
        receiver = owner()
    elif owner is WorkspaceRefusal:
        receiver = owner("invalid_record")
    else:
        assert owner is None, "add fixture construction for the discovered public class"
    bad, arguments, keywords = object(), [], {}
    for parameter in inspect.signature(entry).parameters.values():
        if receiver is not None and parameter.name == "self":
            arguments.append(receiver)
        elif parameter.kind == inspect.Parameter.KEYWORD_ONLY:
            keywords[parameter.name] = bad
        elif parameter.kind == inspect.Parameter.VAR_KEYWORD:
            keywords["unexpected"] = bad
        else:
            arguments.append(bad)
    if not arguments or arguments == [receiver]:
        arguments.append(bad)
    try:
        try:
            result = entry(*arguments, **keywords)
            if hasattr(result, "__enter__"):
                with result:
                    result = None
            elif inspect.isfunction(result):
                result = result()
        except WorkspaceRefusal as error:
            result = error
        assert isinstance(result, WorkspaceRefusal)
        assert result.code == 1 and result.next_action
        assert str(result) == "workspace refused: " + result.reason
    finally:
        if owner is workspace.WorkspaceStore:
            receiver.close()


def test_exports_are_exactly_the_owned_public_definitions():
    for module in (workspace, display):
        tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
        names = set()
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                names.add(node.name)
            elif isinstance(node, ast.Assign):
                names.update(target.id for target in node.targets if isinstance(target, ast.Name))
        expected = {name for name in names if not name.startswith("_")}
        assert hasattr(module, "__all__")
        assert set(module.__all__) == expected
        assert len(module.__all__) == len(expected)


def event(seq, kind, data):
    return {"schema": workspace.EVENT_SCHEMA, "seq": seq, "at": NOW, "kind": kind, "data": data}


def make_store(tmp_path, events=None, name="workspace"):
    if not storage.descriptor_supported():
        pytest.skip("descriptor-relative no-follow storage required")
    root = tmp_path / name
    root.mkdir(mode=0o700)
    (root / "events").mkdir(mode=0o700)
    for row in events or [event(1, "init", LIMITS)]:
        (root / "events" / ("%08d.json" % row["seq"])).write_bytes(workspace.encoded(row) + b"\n")
    return root


def manual_recovery_if_identity_unavailable(root):
    """Owner inspection/removal is explicit test action, as in the legacy CLI."""
    path = root / ".write.lock"
    if path.exists() and json.loads(path.read_bytes())["identity"] == "unavailable":
        with workspace.WorkspaceStore(root) as store:
            with pytest.raises(WorkspaceRefusal) as error:
                with store.lock():
                    pytest.fail("unknown identity was automatically recovered")
            assert_refusal(error, "busy")
        path.unlink()


def assert_refusal(error, reason):
    value = error.value.as_dict()
    assert value == {"status": "refused", "code": 1, "reason": reason,
                     "next_action": error.value.next_action}
    assert value["next_action"]
    assert "secret" not in str(error.value)


@pytest.mark.parametrize("path", ["relative", "/a/../secret", "", None, "x" * 5000],
                         ids=["relative", "traversal", "empty", "none", "oversized"])
def test_absolute_refuses_without_echo(path):
    with pytest.raises(WorkspaceRefusal) as error:
        workspace.absolute(path, "checkout")
    assert_refusal(error, "unsafe_path")
    valid = Path.cwd().as_posix()
    assert workspace.absolute(valid, "checkout") == valid


@pytest.mark.parametrize("data", [{}, {**INITIATIVE, "priority": True},
                                 {**INITIATIVE, "checkouts": ["relative"]},
                                 {**INITIATIVE, "target_branch": "x" * 257}])
def test_validation_refusal_set_matches_legacy(data):
    with pytest.raises(ValueError):
        legacy.validate_initiative(data)
    with pytest.raises(WorkspaceRefusal):
        workspace.validate_initiative(data)
    assert workspace.validate_initiative(INITIATIVE) is None


def test_unsupported_platform_has_typed_refusal(tmp_path, monkeypatch):
    """Accepted delta: legacy has a portable reader; core refuses without descriptors."""
    root = tmp_path / "portable"
    root.mkdir()
    (root / "events").mkdir()
    (root / "events" / "00000001.json").write_bytes(legacy.encoded(event(1, "init", LIMITS)))
    monkeypatch.setattr(legacy, "_memo_supported", lambda: False)
    monkeypatch.setattr(workspace, "descriptor_supported", lambda: False)
    assert legacy.Store(root).load().seq == 1
    with pytest.raises(WorkspaceRefusal) as error:
        workspace.WorkspaceStore(root)
    assert_refusal(error, "unsupported_platform")
    assert legacy.Store(root).load().seq == 1


def test_compatibility_delta_eager_root_binding(tmp_path):
    root = make_store(tmp_path)
    missing = root / "later"
    assert legacy.Store(missing).path == missing
    with pytest.raises(WorkspaceRefusal) as error:
        workspace.WorkspaceStore(missing)
    assert_refusal(error, "missing")
    assert not missing.exists()
    created = make_store(root, name="later")
    with workspace.WorkspaceStore(created) as store:
        assert store.load().seq == legacy.Store(created).load().seq == 1


@pytest.mark.parametrize("field,value,reason", [
    ("repository", "\ud800", "invalid_record"),
    ("checkouts", "x" * 256, "unsafe_path"),
    ("checkouts", "\u00e9" * 128, "unsafe_path"),
], ids=["surrogate", "component_characters", "component_utf8_bytes"])
def test_compatibility_delta_shared_input_bounds(field, value, reason):
    value = [(Path.cwd() / value).as_posix()] if field == "checkouts" else value
    data = {**INITIATIVE, field: value}
    before = deepcopy(data)
    assert legacy.validate_initiative(data) is None
    with pytest.raises(WorkspaceRefusal) as error:
        workspace.validate_initiative(data)
    assert_refusal(error, reason)
    assert data == before
    assert legacy.validate_initiative(INITIATIVE) is workspace.validate_initiative(INITIATIVE) is None


def test_compatibility_delta_pending_entry_census(tmp_path, monkeypatch):
    root = make_store(tmp_path)
    pending = root / "events" / ".pending-probe"
    pending.write_bytes(b"pending")
    # Exercise the same configured ceiling at both public read boundaries.
    monkeypatch.setattr(legacy, "MAX_RECORDS", 1)
    monkeypatch.setattr(storage, "MAX_RECORDS", 1)
    monkeypatch.setattr(workspace, "MAX_RECORDS", 1)
    assert legacy.Store(root).load().seq == 1
    before = {path.name: path.read_bytes() for path in (root / "events").iterdir()}
    with workspace.WorkspaceStore(root) as store:
        with pytest.raises(WorkspaceRefusal) as error:
            store.load()
        assert_refusal(error, "too_large")
        assert {path.name: path.read_bytes() for path in (root / "events").iterdir()} == before
        pending.unlink()
        assert store.load().seq == legacy.Store(root).load().seq == 1


def test_views_and_report_match_same_legacy_bytes(tmp_path, monkeypatch):
    rows = [event(1, "init", LIMITS), event(2, "register", INITIATIVE),
            event(3, "request", {"initiative": "alpha", "kind": "writer", "holder": "writer",
                                 "request_id": "req-00000003"}),
            event(4, "grant", {"request_id": "req-00000003"})]
    root = make_store(tmp_path, rows)
    monkeypatch.setattr(workspace, "timestamp", lambda: NOW)
    monkeypatch.setattr(legacy, "timestamp", lambda: NOW)
    with workspace.WorkspaceStore(root) as store:
        actual, expected = store.load(), legacy.Store(root).load()
        assert ledger_state(actual) == ledger_state(expected)
        assert workspace.capacity_view(actual) == legacy.capacity_view(expected)
        assert workspace.initiative_view(actual, "alpha") == legacy.initiative_view(expected, "alpha")
        assert workspace.check_delivery(actual, "alpha") == legacy.check_delivery(expected, "alpha")
        assert workspace.report(actual) == legacy.report(expected)
        assert workspace.report_text(workspace.report(actual)) == legacy.report_text(legacy.report(expected))
        assert ledger_state(store.load()) == ledger_state(actual)


def test_busy_refuses_once_and_retry_succeeds(tmp_path):
    root = make_store(tmp_path)
    with workspace.WorkspaceStore(root) as first, workspace.WorkspaceStore(root) as second:
        with first.lock():
            with pytest.raises(WorkspaceRefusal) as error:
                with second.lock():
                    pytest.fail("contending writer entered")
            assert_refusal(error, "busy")
            assert "abandoned lock" in error.value.next_action
        with second.lock():
            assert second.load().seq == 1
    assert not (root / ".write.lock").exists()


@pytest.mark.parametrize("kind,limit", [("heavy", 3), ("heavy-tests", 1)])
def test_over_capacity_refuses_without_state_change_then_retries(tmp_path, kind, limit):
    root = make_store(tmp_path)
    with workspace.WorkspaceStore(root) as store, store.lock():
        ledger = store.load()
        store.append(ledger, "register", INITIATIVE)
        for index in range(limit + 1):
            identifier = "req-%08d" % (ledger.seq + 1)
            store.append(ledger, "request", {"initiative": "alpha", "kind": kind,
                                             "holder": "writer-%d" % index, "request_id": identifier})
            if index < limit:
                store.append(ledger, "grant", {"request_id": identifier})
        before, names = ledger_state(ledger), sorted((root / "events").iterdir())
        with pytest.raises(WorkspaceRefusal) as error:
            store.append(ledger, "grant", {"request_id": identifier})
        assert_refusal(error, "capacity_full")
        assert ledger_state(ledger) == before
        assert sorted((root / "events").iterdir()) == names
        held = ledger.held(kind)[0]["request_id"]
        store.append(ledger, "release", {"request_id": held,
                     "evidence": {"path": str(root / "evidence"), "sha256": "0" * 64}})
        store.append(ledger, "grant", {"request_id": identifier})
        assert ledger_state(store.load()) == ledger_state(ledger)


def test_two_concurrent_grants_use_one_slot(tmp_path):
    root = make_store(tmp_path, [event(1, "init", LIMITS), event(2, "register", INITIATIVE),
        event(3, "request", {"initiative": "alpha", "kind": "heavy-tests", "holder": "one",
                             "request_id": "req-00000003"}),
        event(4, "request", {"initiative": "alpha", "kind": "heavy-tests", "holder": "two",
                             "request_id": "req-00000004"})])

    def grant():
        try:
            with workspace.WorkspaceStore(root) as store:
                return workspace.grant_next(store, "heavy-tests")[0]
        except WorkspaceRefusal as error:
            assert error.reason == "busy"
            return error.reason

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [future.result(timeout=5) for future in [pool.submit(grant), pool.submit(grant)]]
    assert results.count(0) == 1
    with workspace.WorkspaceStore(root) as store:
        assert len(store.load().held("heavy-tests")) == 1
        assert workspace.grant_next(store, "heavy-tests")[1]["reason"] == "capacity_full"


def test_publication_failure_preserves_ledger_and_retry(tmp_path, monkeypatch):
    root = make_store(tmp_path)
    with workspace.WorkspaceStore(root) as store, store.lock():
        ledger = store.load()
        before = ledger_state(ledger)
        publish = workspace.WorkspaceStore.publish
        def unavailable(*args, **kwargs):
            raise OSError("secret")
        monkeypatch.setattr(workspace.WorkspaceStore, "publish", unavailable)
        with pytest.raises(WorkspaceRefusal) as error:
            store.append(ledger, "register", INITIATIVE)
        assert_refusal(error, "io")
        assert ledger_state(ledger) == before
        monkeypatch.setattr(workspace.WorkspaceStore, "publish", publish)
        store.append(ledger, "register", INITIATIVE)
        assert store.load().seq == 2


def test_root_rename_does_not_redirect_reads_or_writes(tmp_path):
    root = make_store(tmp_path)
    with workspace.WorkspaceStore(root) as store:
        held = root.with_name("held")
        root.rename(held)
        root.mkdir(mode=0o700)
        (root / "events").mkdir(mode=0o700)
        with store.lock():
            ledger = store.load()
            store.append(ledger, "register", INITIATIVE)
        assert list((root / "events").iterdir()) == []
        assert (held / "events" / "00000002.json").is_file()


def test_symlink_component_and_event_refuse_then_retry(tmp_path):
    root = make_store(tmp_path)
    alias = tmp_path / "alias"
    symlink_or_skip(root, alias, target_is_directory=True)
    with pytest.raises(WorkspaceRefusal) as error:
        workspace.WorkspaceStore(alias)
    assert_refusal(error, "unsafe_path")
    record = root / "events" / "00000001.json"
    raw = record.read_bytes()
    record.unlink()
    source = tmp_path / "secret"
    source.write_bytes(raw)
    symlink_or_skip(source, record)
    with workspace.WorkspaceStore(root) as store:
        with pytest.raises(WorkspaceRefusal) as error:
            store.load()
        assert_refusal(error, "unsafe_path")
        record.unlink()
        record.write_bytes(raw)
        assert store.load().seq == 1


@pytest.mark.parametrize("raw", [b"{", b'{}', b'\xff', b'{"x":1,"x":2}', b'[' * 1000,
                                 b' ' * (workspace.MAX_BYTES + 1)],
                         ids=["syntax", "schema", "encoding", "duplicate", "depth", "oversized"])
def test_malformed_or_oversized_event_is_typed_and_recoverable(tmp_path, raw):
    root = make_store(tmp_path)
    path = root / "events" / "00000001.json"
    good = path.read_bytes()
    path.write_bytes(raw)
    with workspace.WorkspaceStore(root) as store:
        with pytest.raises(WorkspaceRefusal) as error:
            store.load()
        assert error.value.reason in {"invalid_record", "too_large"}
        path.write_bytes(good)
        assert store.load().seq == 1


def test_evidence_is_bounded_and_descriptor_read(tmp_path, monkeypatch):
    root = make_store(tmp_path)
    path = root / "proof"
    path.write_bytes(b"proof")
    reference = {"path": str(path), "sha256": hashlib.sha256(b"proof").hexdigest()}
    assert workspace.verify_evidence(reference) is None
    limit = workspace.MAX_EVIDENCE_BYTES
    monkeypatch.setattr(workspace, "MAX_EVIDENCE_BYTES", 4)
    with pytest.raises(WorkspaceRefusal) as error:
        workspace.verify_evidence(reference)
    assert_refusal(error, "too_large")
    monkeypatch.setattr(workspace, "MAX_EVIDENCE_BYTES", limit)
    assert workspace.verify_evidence(reference) is None
    with pytest.raises(WorkspaceRefusal) as error:
        workspace.verify_evidence({**reference, "sha256": "0" * 64})
    assert_refusal(error, "evidence_mismatch")


def test_lease_and_mailbox_readers_are_injected():
    ledger = workspace.Ledger()
    ledger.apply(event(1, "init", LIMITS))
    ledger.apply(event(2, "register", INITIATIVE))
    with pytest.raises(WorkspaceRefusal) as error:
        workspace.check_paths(ledger, "alpha", ["a.py"])
    assert_refusal(error, "port_required")
    ports = legacy.lease_tools()
    assert workspace.check_paths(ledger, "alpha", ["a.py"], lease_ports=ports) == legacy.check_paths(
        ledger, "alpha", ["a.py"])
    assert workspace.mailbox_facts(INITIATIVE) is None
    fake = SimpleNamespace(status=lambda: {"messages": 2, "open_job_requests": [], "accepted_writers": []})
    assert workspace.mailbox_facts({**INITIATIVE, "mailbox_root": "/mail"},
                                    mailbox_factory=lambda path: fake)["messages"] == 2


def ledger_state(ledger):
    return {"seq": ledger.seq, "limits": deepcopy(ledger.limits),
            "initiatives": deepcopy(ledger.initiatives), "requests": deepcopy(ledger.requests),
            "capacity": workspace.capacity_view(ledger)}


@pytest.mark.parametrize("operation", ["write", "link", "directory_sync", "pending_cleanup"])
def test_publication_io_failures_close_descriptors_and_retry(tmp_path, monkeypatch, operation):
    root = make_store(tmp_path)
    with workspace.WorkspaceStore(root) as store, store.lock():
        ledger = store.load()
        before = ledger_state(ledger)
        opened, failed = [], []
        real_open, real_write, real_link = os.open, os.write, os.link
        real_sync, real_unlink = os.fsync, os.unlink
        def track_open(*args, **kwargs):
            descriptor = real_open(*args, **kwargs)
            opened.append(descriptor)
            return descriptor
        def fail_write(*args, **kwargs):
            if operation == "write":
                raise OSError("secret")
            return real_write(*args, **kwargs)
        def fail_link(*args, **kwargs):
            if operation == "link":
                raise OSError("secret")
            return real_link(*args, **kwargs)
        def fail_sync(descriptor):
            if operation == "directory_sync" and stat.S_ISDIR(os.fstat(descriptor).st_mode):
                raise OSError("secret")
            return real_sync(descriptor)
        def fail_cleanup(name, **kwargs):
            if operation == "pending_cleanup" and name.startswith(".pending-") and not failed:
                failed.append(True)
                raise OSError("secret")
            return real_unlink(name, **kwargs)
        owned_os = SimpleNamespace(**{**vars(workspace.os), "open": track_open, "write": fail_write,
                                      "link": fail_link, "fsync": fail_sync, "unlink": fail_cleanup})
        monkeypatch.setattr(workspace, "os", owned_os)
        with pytest.raises(WorkspaceRefusal) as error:
            store.append(ledger, "register", INITIATIVE)
        assert_refusal(error, "io")
        monkeypatch.setattr(workspace, "os", os)
        assert ledger_state(ledger) == before
        assert [path.name for path in (root / "events").iterdir()] == ["00000001.json"]
        for descriptor in opened:
            with pytest.raises(OSError):
                os.fstat(descriptor)
        store.append(ledger, "register", INITIATIVE)
        assert store.load().seq == 2


def test_event_directory_swap_during_read_stays_on_held_descriptor(tmp_path, monkeypatch):
    root = make_store(tmp_path)
    outside = make_store(tmp_path, name="outside")
    with workspace.WorkspaceStore(root) as store:
        read = workspace._Files.read
        changed = []
        def swap_then_read(self, path, **kwargs):
            if not changed:
                (root / "events").rename(root / "held-events")
                symlink_or_skip(outside / "events", root / "events", target_is_directory=True)
                changed.append(True)
            return read(self, path, **kwargs)
        monkeypatch.setattr(workspace._Files, "read", swap_then_read)
        assert store.load().seq == 1
        assert (outside / "events" / "00000001.json").read_bytes() == (
            root / "held-events" / "00000001.json").read_bytes()


@pytest.mark.parametrize("kind", ["heavy", "heavy-tests"])
def test_grant_next_nonerror_full_matches_legacy(tmp_path, kind):
    limits = {"writer_limit": 5, "heavy_limit": 1, "heavy_tests_limit": 1}
    root = make_store(tmp_path, [event(1, "init", limits), event(2, "register", INITIATIVE),
        event(3, "request", {"initiative": "alpha", "kind": kind, "holder": "one",
                             "request_id": "req-00000003"}),
        event(4, "grant", {"request_id": "req-00000003"})])
    with workspace.WorkspaceStore(root) as store:
        assert workspace.grant_next(store, kind) == legacy.grant_next(legacy.Store(root), kind)


def test_supersede_replay_and_timing_unknown_match_legacy(tmp_path):
    rows = [event(1, "init", LIMITS), event(2, "register", INITIATIVE),
        event(3, "request", {"initiative": "alpha", "kind": "writer", "holder": "one",
                             "request_id": "req-00000003"}),
        {**event(4, "request", {"initiative": "alpha", "kind": "writer", "holder": "one",
                               "request_id": "req-00000004", "supersedes": "req-00000003"}),
         "schema": workspace.SUPERSEDE_EVENT_SCHEMA, "at": "invalid"}]
    root = make_store(tmp_path, rows)
    with workspace.WorkspaceStore(root) as store:
        with pytest.raises(WorkspaceRefusal):
            store.load()
        actual, expected = store.load(for_report=True), legacy.Store(root).load(for_report=True)
        assert ledger_state(actual) == ledger_state(expected)
        assert workspace.queue_facts(actual, NOW) == legacy.queue_facts(expected, NOW)


def test_legacy_sources_stay_at_claim_bytes_without_git_history():
    root = Path(__file__).resolve().parents[3]
    expected = {"hierarchy_workspace.py": "89716178d61b79fcc7d1f67d473f71d2847aa3e251237908325cf838fe8a6e5f",
                "hierarchy_workspace_display.py": "d57ed96be1f41362716e5570d67b9f193d3e8f828cf804ded013bd7ff9abb0ec"}
    for name, digest in expected.items():
        text = (root / "tools" / name).read_text(encoding="utf-8")
        assert hashlib.sha256(text.encode("utf-8")).hexdigest() == digest


def test_observer_failure_is_typed_and_releases_lock_for_retry(tmp_path):
    root = make_store(tmp_path)
    def unavailable(ledger):
        raise RuntimeError("secret")
    with workspace.WorkspaceStore(root) as store:
        with pytest.raises(WorkspaceRefusal) as error:
            workspace.grant_next(store, "heavy", outside=unavailable)
        assert_refusal(error, "port_unavailable")
        assert workspace.grant_next(store, "heavy")[1]["reason"] == "queue_empty"


def test_report_text_screens_untrusted_fields(monkeypatch):
    """Accepted delta: text is screened while successful structured values match."""
    monkeypatch.setattr(workspace, "timestamp", lambda: NOW)
    monkeypatch.setattr(legacy, "timestamp", lambda: NOW)
    ledger, old_ledger = workspace.Ledger(), legacy.Ledger()
    for row in (event(1, "init", LIMITS),
                event(2, "register", {**INITIATIVE, "blocked_by": ["password=hunter2\n"]})):
        ledger.apply(row)
        old_ledger.apply(row)
    report, old_report = workspace.report(ledger), legacy.report(old_ledger)
    before = deepcopy(report)
    assert report == old_report
    assert "password=hunter2\n" in legacy.report_text(old_report)
    result = workspace.report_text(report)
    assert "hunter2" not in result
    assert "blocked by <redacted" in result
    assert report == before


def test_successful_append_preserves_request_references_like_legacy(tmp_path):
    root = make_store(tmp_path, [event(1, "init", LIMITS), event(2, "register", INITIATIVE),
        event(3, "request", {"initiative": "alpha", "kind": "writer", "holder": "one",
                             "request_id": "req-00000003"})])
    with workspace.WorkspaceStore(root) as store, store.lock():
        ledger = store.load()
        request = ledger.request("req-00000003")
        store.append(ledger, "grant", {"request_id": request["request_id"]})
        assert request["state"] == "granted"
        assert workspace.request_view(request) == workspace.request_view(ledger.request(request["request_id"]))


def test_evidence_parent_swap_is_confined_and_missing_evidence_can_retry(tmp_path, monkeypatch):
    root = make_store(tmp_path)
    outside = make_store(tmp_path, name="outside")
    proof = root / "proof"
    proof.write_bytes(b"proof")
    (outside / "proof").write_bytes(b"decoy")
    reference = {"path": str(proof), "sha256": hashlib.sha256(b"proof").hexdigest()}
    read, changed = workspace._Files.read, []
    def swap_then_read(self, path, **kwargs):
        if path == proof and not changed:
            root.rename(tmp_path / "held")
            symlink_or_skip(outside, root, target_is_directory=True)
            changed.append(True)
        return read(self, path, **kwargs)
    monkeypatch.setattr(workspace._Files, "read", swap_then_read)
    assert workspace.verify_evidence(reference) is None
    assert (outside / "proof").read_bytes() == b"decoy"
    missing = outside / "missing"
    reference = {"path": str(missing), "sha256": hashlib.sha256(b"proof").hexdigest()}
    with pytest.raises(WorkspaceRefusal) as error:
        workspace.verify_evidence(reference)
    assert_refusal(error, "missing")
    missing.write_bytes(b"proof")
    assert workspace.verify_evidence(reference) is None


def _request_data():
    return {"initiative": "alpha", "request_id": "req-00000003", "kind": "writer", "holder": "one"}


def _initialized_ledger():
    ledger = workspace.Ledger()
    ledger.apply(event(1, "init", LIMITS))
    ledger.apply(event(2, "register", INITIATIVE))
    return ledger


@pytest.mark.parametrize("field", sorted(_request_data()))
@pytest.mark.parametrize("bad", [[], {}], ids=["array", "object"])
def test_request_field_shapes_refuse_without_mutation_then_retry(field, bad):
    ledger = _initialized_ledger()
    before = ledger_state(ledger)
    with pytest.raises(WorkspaceRefusal) as error:
        ledger.apply(event(3, "request", {**_request_data(), field: bad}))
    assert_refusal(error, "invalid_record")
    assert ledger_state(ledger) == before
    ledger.apply(event(3, "request", _request_data()))
    assert ledger.request("req-00000003")["state"] == "queued"


@pytest.mark.parametrize("bad", [[], {}], ids=["array", "object"])
def test_unhashable_event_kind_is_fixed_refusal_and_retries(bad):
    ledger = _initialized_ledger()
    before = ledger_state(ledger)
    with pytest.raises(WorkspaceRefusal) as error:
        ledger.apply(event(3, bad, _request_data()))
    assert_refusal(error, "invalid_record")
    assert ledger_state(ledger) == before
    ledger.apply(event(3, "request", _request_data()))
    assert ledger.seq == 3


@pytest.mark.parametrize("bad", [[], {}], ids=["array", "object"])
def test_unhashable_replay_schema_is_fixed_refusal_and_retries(tmp_path, bad):
    root = make_store(tmp_path)
    record = root / "events" / "00000001.json"
    good = record.read_bytes()
    raw = workspace.encoded({**event(1, "init", LIMITS), "schema": bad})
    record.write_bytes(raw)
    with workspace.WorkspaceStore(root) as store:
        with pytest.raises(WorkspaceRefusal) as error:
            store.load()
        assert_refusal(error, "invalid_record")
        assert record.read_bytes() == raw
        record.write_bytes(good)
        assert store.load().seq == 1


@pytest.mark.parametrize("bad", [None, object(), [[]]], ids=["none", "opaque", "nested_array"])
def test_field_declaration_shape_refuses_before_set_conversion(bad):
    with pytest.raises(WorkspaceRefusal) as error:
        workspace.fields({"x": 1}, bad)
    assert_refusal(error, "invalid_record")
    assert workspace.fields({"x": 1}, {"x"}) is None


@pytest.mark.parametrize("field", ["used", "limit"])
@pytest.mark.parametrize("bad", [[], {}], ids=["array", "object"])
def test_report_numeric_shapes_refuse_before_formatting_then_retry(field, bad):
    report = workspace.report(_initialized_ledger())
    valid = deepcopy(report)
    report["capacity"]["writer"][field] = bad
    before = deepcopy(report)
    with pytest.raises(WorkspaceRefusal) as error:
        workspace.report_text(report)
    assert_refusal(error, "invalid_record")
    assert report == before
    assert isinstance(workspace.report_text(valid), str)


@pytest.mark.parametrize("bad", [None, [], {}, False], ids=["null", "array", "object", "boolean"])
def test_wrong_timing_types_keep_legacy_unknown_outcome(bad):
    ledger = _initialized_ledger()
    ledger.apply(event(3, "request", _request_data()))
    request = ledger.request("req-00000003")
    request["requested_at"] = bad
    before = ledger_state(ledger)
    result = workspace.queue_facts(ledger, NOW)
    assert result == legacy.queue_facts(ledger, NOW)
    assert result["writer"]["timing_unknown"] == 1
    assert ledger_state(ledger) == before
    request["requested_at"] = NOW
    assert workspace.queue_facts(ledger, NOW)["writer"]["timing_unknown"] == 0


@pytest.mark.parametrize("bad", [None, {"messages": 0, "open_job_requests": None, "accepted_writers": []}],
                         ids=["status_object", "request_collection"])
def test_mailbox_status_shape_keeps_operational_refusal_and_closes_port(bad):
    closed = []
    mailbox = SimpleNamespace(status=lambda: bad, close=lambda: closed.append(True))
    with pytest.raises(WorkspaceRefusal) as error:
        workspace.mailbox_facts({"mailbox_root": Path.cwd().as_posix()}, mailbox_factory=lambda root: mailbox)
    assert_refusal(error, "invalid_record")
    assert closed == [True]


def test_mailbox_delivery_shape_refuses_before_numeric_sum_and_closes_port():
    closed = []
    mailbox = SimpleNamespace(
        status=lambda: {"messages": 0, "open_job_requests": [], "accepted_writers": []},
        delivery=lambda root: {"endpoints": {"lane": {"unread_count": None}}},
        close=lambda: closed.append(True))
    with pytest.raises(WorkspaceRefusal) as error:
        workspace.mailbox_facts({"mailbox_root": Path.cwd().as_posix(), "delivery_dir": Path.cwd().as_posix()},
                                mailbox_factory=lambda root: mailbox)
    assert_refusal(error, "invalid_record")
    assert closed == [True]


def test_mailbox_shape_refusal_allows_valid_retry_with_legacy_facts():
    response, closed = [None], []
    def factory(root):
        return SimpleNamespace(status=lambda: response[0], close=lambda: closed.append(True),
            delivery=lambda destination: {"endpoints": {"one": {"unread_count": 1}, "two": {"unread_count": 2}}})
    initiative = {"mailbox_root": Path.cwd().as_posix(), "delivery_dir": Path.cwd().as_posix()}
    with pytest.raises(WorkspaceRefusal) as error:
        workspace.mailbox_facts(initiative, mailbox_factory=factory)
    assert_refusal(error, "invalid_record")
    response[0] = {"messages": 2, "open_job_requests": ["one"], "accepted_writers": ["one"]}
    assert workspace.mailbox_facts(initiative, mailbox_factory=factory) == {
        "messages": 2, "open_job_requests": 1, "accepted_writers": 1, "unread": 3}
    assert closed == [True, True]


@pytest.mark.parametrize("payload", list(credential_positions(2)))
def test_generated_observer_credential_positions_are_screened(tmp_path, payload):
    root = make_store(tmp_path)
    with workspace.WorkspaceStore(root) as store:
        code, result = workspace.grant_next(store, "heavy-tests", lambda ledger: [payload])
        assert code == 3 and result["reason"] == "capacity_full"
        assert "hunter2" not in repr(result)
        assert store.load().seq == 1


def test_resulting_capacity_counts_stale_pending_before_publication(tmp_path, monkeypatch):
    root = make_store(tmp_path, [event(1, "init", LIMITS), event(2, "register", INITIATIVE)])
    pending = root / "events" / ".pending-stale"
    pending.write_bytes(b"stale")
    monkeypatch.setattr(workspace, "MAX_RECORDS", 3)
    monkeypatch.setattr(storage, "MAX_RECORDS", 3)
    with workspace.WorkspaceStore(root) as store, store.lock():
        ledger = store.load()
        before = {p.name: p.read_bytes() for p in (root / "events").iterdir()}
        with pytest.raises(WorkspaceRefusal) as error:
            store.append(ledger, "request", _request_data())
        assert_refusal(error, "too_large")
        assert ledger.seq == 2
        assert {p.name: p.read_bytes() for p in (root / "events").iterdir()} == before
        pending.unlink()
        store.append(ledger, "request", _request_data())
        assert store.load().seq == 3


def test_concurrent_reader_accepts_only_own_publication_pair(tmp_path, monkeypatch):
    root = make_store(tmp_path)
    monkeypatch.setattr(workspace, "MAX_RECORDS", 2)
    linked, resume = Event(), Event()
    real_link = os.link
    def pause_after_link(*args, **kwargs):
        real_link(*args, **kwargs)
        linked.set()
        assert resume.wait(5)
    owned_os = SimpleNamespace(**{**vars(workspace.os), "link": pause_after_link})
    monkeypatch.setattr(workspace, "os", owned_os)
    with workspace.WorkspaceStore(root) as writer, workspace.WorkspaceStore(root) as reader:
        def publish():
            with writer.lock():
                writer.append(writer.load(), "register", INITIATIVE)
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(publish)
            try:
                assert linked.wait(5)
                assert reader.load().seq == legacy.Store(root).load().seq == 2
            finally:
                resume.set()
            future.result(timeout=5)
        assert reader.load().seq == 2
        real_link(root / "events" / "00000002.json", root / "unrelated-link")
        with pytest.raises(WorkspaceRefusal) as error:
            reader.load()
        assert_refusal(error, "unsafe_path")
        (root / "unrelated-link").unlink()
        assert reader.load().seq == 2


def test_committed_grant_survives_cleanup_and_next_writer_recovers(tmp_path, monkeypatch):
    root = make_store(tmp_path, [event(1, "init", LIMITS), event(2, "register", INITIATIVE),
                               event(3, "request", _request_data())])
    real_unlink = os.unlink
    failed = []
    def fail_release(name, **kwargs):
        if name == ".write.lock" and not failed:
            failed.append(True)
            raise OSError("password=hunter2")
        return real_unlink(name, **kwargs)
    monkeypatch.setattr(workspace, "os", SimpleNamespace(**{**vars(workspace.os), "unlink": fail_release}))
    with workspace.WorkspaceStore(root) as store:
        code, result = workspace.grant_next(store, "writer")
        assert code == 0 and result["granted"]["state"] == "granted"
        assert result["warnings"][0]["reason"] == "lock_release"
        assert result["warnings"][0]["next_action"]
        validate_warnings(result["warnings"])
        assert "hunter2" not in repr(result)
        assert store.load().requests[result["granted"]["request_id"]]["state"] == "granted"
    manual_recovery_if_identity_unavailable(root)
    with workspace.WorkspaceStore(root) as retry:
        assert workspace.grant_next(retry, "writer")[1]["reason"] == "queue_empty"
    assert not (root / ".write.lock").exists()


@pytest.mark.parametrize("sticky", [False, True])
def test_trusted_root_owned_parent_keeps_legacy_success(tmp_path, monkeypatch, sticky):
    root = make_store(tmp_path)
    proof = root / "proof"
    proof.write_bytes(b"proof")
    reference = {"path": str(proof), "sha256": hashlib.sha256(b"proof").hexdigest()}
    parent = os.stat(tmp_path)
    root_uid = 0
    real_fstat = workspace.os.fstat
    def parent_policy(fd):
        info = real_fstat(fd)
        if (info.st_dev, info.st_ino) == (parent.st_dev, parent.st_ino):
            return stat_observation(info, stat.S_IFDIR | (0o1777 if sticky else 0o755), root_uid)
        return info
    proxy = SimpleNamespace(**{**vars(workspace.os), "fstat": parent_policy})
    monkeypatch.setattr(workspace, "os", proxy)
    # The actual filesystem still supplies all descriptors and bytes; only
    # parent ownership/mode observation models /home and /tmp cross-platform.
    assert legacy.Store(root).load().seq == 1
    assert legacy.verify_evidence(reference) is None
    with workspace.WorkspaceStore(root) as store:
        assert store.load().seq == 1
    assert workspace.verify_evidence(reference) is None


@pytest.mark.skipif(os.name != "posix", reason="POSIX backslash declaration semantics")
def test_posix_backslash_declaration_keeps_legacy_acceptance():
    value = "/tmp/a\\b"
    assert workspace.absolute(value, "path") == legacy.absolute(value, "path") == value
    assert workspace.validate_initiative({**INITIATIVE, "checkouts": [value]}) is None


def test_replay_reuses_unchanged_appends_incrementally_and_rewrites_fully(tmp_path, monkeypatch):
    root = make_store(tmp_path)
    real_json, reads = workspace.strict_json, []
    def count_parse(raw):
        reads.append(raw)
        return real_json(raw)
    monkeypatch.setattr(workspace, "strict_json", count_parse)
    with workspace.WorkspaceStore(root) as store:
        first = store.load()
        assert len(reads) == 1
        first.limits["writer"] = 999
        assert store.load().limits["writer"] == 5
        assert len(reads) == 1
        with store.lock():
            store.append(store.load(), "register", INITIATIVE)
        assert store.load().seq == 2
        assert len(reads) == 2
        path = root / "events" / "00000002.json"
        path.write_bytes(workspace.encoded(event(2, "register", {**INITIATIVE, "project": "revised"})))
        assert store.load().initiatives["alpha"]["project"] == "revised"
        assert len(reads) == 4
        assert store.load(for_report=True).seq == 2
        assert len(reads) == 6


@pytest.mark.parametrize("owner,mode", [("owner", 0o777), ("owner", 0o770), ("foreign", 0o755),
                                       ("foreign", 0o1777)])
def test_untrusted_ancestor_refuses_before_read_then_retries(tmp_path, monkeypatch, owner, mode):
    root = make_store(tmp_path)
    target = os.stat(tmp_path)
    real_fstat, owned_os = workspace.os.fstat, workspace.os
    def untrusted(fd):
        info = real_fstat(fd)
        if (info.st_dev, info.st_ino) == (target.st_dev, target.st_ino):
            return stat_observation(info, stat.S_IFDIR | mode, os.geteuid() if owner == "owner" else 123456)
        return info
    monkeypatch.setattr(workspace, "os", SimpleNamespace(**{**vars(owned_os), "fstat": untrusted}))
    before = (root / "events" / "00000001.json").read_bytes()
    with pytest.raises(WorkspaceRefusal) as error:
        workspace.WorkspaceStore(root)
    assert_refusal(error, "unsafe_path")
    assert (root / "events" / "00000001.json").read_bytes() == before
    monkeypatch.setattr(workspace, "os", owned_os)
    with workspace.WorkspaceStore(root) as store:
        assert store.load().seq == 1


def test_failed_constructor_closes_every_opened_descriptor(tmp_path, monkeypatch):
    root = make_store(tmp_path)
    owned_os, opened = workspace.os, []
    def track_open(*args, **kwargs):
        fd = os.open(*args, **kwargs)
        opened.append(fd)
        return fd
    def fail_stat(fd):
        raise OSError("password=hunter2")
    monkeypatch.setattr(workspace, "os", SimpleNamespace(**{**vars(owned_os), "open": track_open,
                                                           "fstat": fail_stat}))
    with pytest.raises(WorkspaceRefusal) as error:
        workspace.WorkspaceStore(root)
    assert_refusal(error, "io")
    for fd in opened:
        with pytest.raises(OSError):
            os.fstat(fd)
    monkeypatch.setattr(workspace, "os", owned_os)
    with workspace.WorkspaceStore(root) as store:
        assert store.load().seq == 1


def test_cleanup_failure_without_commit_refuses_then_recovers_own_stale_lock(tmp_path, monkeypatch):
    root = make_store(tmp_path)
    owned_os = workspace.os
    def fail_release(name, **kwargs):
        if name == ".write.lock":
            raise OSError("password=hunter2")
        return os.unlink(name, **kwargs)
    with workspace.WorkspaceStore(root) as store:
        monkeypatch.setattr(workspace, "os", SimpleNamespace(**{**vars(owned_os), "unlink": fail_release}))
        with pytest.raises(WorkspaceRefusal) as error:
            with store.lock():
                store.append(store.load(), "register", {})
        assert error.value.code == 1 and error.value.next_action
        assert store.load().seq == 1
        monkeypatch.setattr(workspace, "os", owned_os)
        manual_recovery_if_identity_unavailable(root)
        with store.lock():
            store.append(store.load(), "register", INITIATIVE)
        assert store.load().seq == 2


def test_stale_lock_recovery_never_removes_replaced_lock(tmp_path, monkeypatch):
    root = make_store(tmp_path)
    owned_os = workspace.os
    def fail_release(name, **kwargs):
        if name == ".write.lock":
            raise OSError("release failed")
        return os.unlink(name, **kwargs)
    with workspace.WorkspaceStore(root) as store:
        monkeypatch.setattr(workspace, "os", SimpleNamespace(**{**vars(owned_os), "unlink": fail_release}))
        with store.lock():
            store.append(store.load(), "register", INITIATIVE)
        monkeypatch.setattr(workspace, "os", owned_os)
    lock = root / ".write.lock"
    lock.unlink()
    lock.write_bytes(b"another writer")
    lock.chmod(0o600)
    with workspace.WorkspaceStore(root) as retry:
        with pytest.raises(WorkspaceRefusal) as error:
            with retry.lock():
                pytest.fail("replaced lock was removed")
        assert_refusal(error, "busy")
        assert lock.read_bytes() == b"another writer"
        lock.unlink()
        with retry.lock():
            assert retry.load().seq == 2


def test_cache_failed_rewrite_refuses_and_restored_history_retries(tmp_path):
    root = make_store(tmp_path)
    path = root / "events" / "00000001.json"
    good = path.read_bytes()
    with workspace.WorkspaceStore(root) as store:
        assert store.load().seq == 1
        path.write_bytes(b"{")
        with pytest.raises(WorkspaceRefusal) as error:
            store.load()
        assert_refusal(error, "invalid_record")
        path.write_bytes(good)
        assert store.load().seq == 1


def test_filesystem_metadata_never_teaches_an_additional_trusted_uid(tmp_path, monkeypatch):
    root = make_store(tmp_path)
    owned_os = workspace.os
    root_info, target = os.stat(Path(root.anchor)), os.stat(tmp_path)
    identities = {(info.st_dev, info.st_ino) for info in (root_info, target)}
    def foreign_root(fd):
        info = owned_os.fstat(fd)
        if info.st_uid == 0 or (info.st_dev, info.st_ino) in identities:
            return stat_observation(info, stat.S_IFDIR | 0o755, 123456)
        return info
    monkeypatch.setattr(workspace, "os", SimpleNamespace(**{**vars(owned_os), "fstat": foreign_root}))
    with pytest.raises(WorkspaceRefusal) as error:
        workspace.WorkspaceStore(root)
    assert_refusal(error, "unsafe_path")
    monkeypatch.setattr(workspace, "os", owned_os)
    with workspace.WorkspaceStore(root) as store:
        assert store.load().seq == 1


def test_reader_retries_when_link_appears_after_directory_name_snapshot(tmp_path, monkeypatch):
    root = make_store(tmp_path)
    pending = root / "events" / (".pending-" + "a" * 32)
    pending.write_bytes(workspace.encoded(event(2, "register", INITIATIVE)))
    linked = []
    real_stat = os.stat
    def link_before_stat(name, **kwargs):
        if name == pending.name and not linked:
            os.link(pending.name, "00000002.json", src_dir_fd=kwargs["dir_fd"],
                    dst_dir_fd=kwargs["dir_fd"], follow_symlinks=False)
            linked.append(True)
        return real_stat(name, **kwargs)
    with workspace.WorkspaceStore(root) as store:
        monkeypatch.setattr(workspace, "os", SimpleNamespace(**{**vars(workspace.os), "stat": link_before_stat}))
        assert store.load().seq == legacy.Store(root).load().seq == 2
        pending.unlink()
        assert store.load().seq == 2


def real_owner(path, uid):
    """Real ownership tests run only where this UID can set the requested owner."""
    if path.stat().st_uid != uid:
        try:
            os.chown(path, uid, -1)
        except OSError as error:
            if error.errno not in (errno.EPERM, errno.EACCES, errno.EINVAL, errno.ENOTSUP):
                raise
            pytest.skip("changing directory/file ownership requires an OS capability")


@pytest.mark.parametrize("ancestor", ["owner", "root0755", "root0711", "sticky1777"])
@pytest.mark.parametrize("coordination", ["owner0700", "owner0775", "root1777", "foreign"])
@pytest.mark.parametrize("target", ["workspace", "events", "evidence"])
def test_generated_real_ancestor_coordination_matrix(tmp_path, ancestor, coordination, target):
    if os.name != "posix":
        pytest.skip("POSIX directory ownership and modes")
    parent = tmp_path / "ancestor"
    parent.mkdir(mode=0o700)
    root = make_store(parent)
    proof = root / "proof"
    proof.write_bytes(b"proof")
    reference = {"path": str(proof), "sha256": hashlib.sha256(b"proof").hexdigest()}
    folder = root / "events" if target == "events" else root
    try:
        if ancestor != "owner":
            real_owner(parent, 0)
            parent.chmod({"root0755": 0o755, "root0711": 0o711, "sticky1777": 0o1777}[ancestor])
        if coordination == "root1777":
            real_owner(folder, 0)
        elif coordination == "foreign":
            real_owner(folder, 65533 if os.geteuid() != 65533 else 65532)
        folder.chmod({"owner0700": 0o700, "owner0775": 0o775, "root1777": 0o1777,
                      "foreign": 0o755}[coordination])
        def check():
            if target == "evidence":
                return workspace.verify_evidence(reference)
            with workspace.WorkspaceStore(root) as store:
                return store.load().seq
        if coordination == "owner0700" or (target == "evidence" and coordination == "root1777"):
            assert check() == (None if target == "evidence" else 1)
        else:
            with pytest.raises(WorkspaceRefusal) as error:
                check()
            assert_refusal(error, "unsafe_path")
    finally:
        # Restore real permissions/ownership for pytest's cross-platform cleanup.
        if folder.stat().st_uid == os.geteuid():
            folder.chmod(0o700)
        else:
            os.chown(folder, os.geteuid(), -1)
            folder.chmod(0o700)
        if parent.stat().st_uid != os.geteuid():
            os.chown(parent, os.geteuid(), -1)
        parent.chmod(0o700)


@pytest.mark.parametrize("api", ["store", "evidence"])
@pytest.mark.parametrize("component", ["ancestor", "coordination"])
def test_search_only_real_ancestor_keeps_legacy_success(tmp_path, api, component):
    if os.name != "posix" or not hasattr(os, "O_PATH"):
        pytest.skip("search-only directory descriptors required")
    parent = tmp_path / "search-only"
    parent.mkdir(mode=0o700)
    root = make_store(parent)
    proof = root / "proof"
    proof.write_bytes(b"proof")
    reference = {"path": str(proof), "sha256": hashlib.sha256(b"proof").hexdigest()}
    search_only = parent if component == "ancestor" else root
    search_only.chmod(0o111)
    try:
        if api == "store":
            assert legacy.Store(root).load().seq == 1
            with workspace.WorkspaceStore(root) as store:
                assert store.load().seq == 1
        else:
            assert legacy.verify_evidence(reference) is None
            assert workspace.verify_evidence(reference) is None
    finally:
        search_only.chmod(0o700)


def test_foreign_owned_event_refuses_before_read_and_retries(tmp_path):
    if os.name != "posix":
        pytest.skip("POSIX file ownership")
    root = make_store(tmp_path)
    record = root / "events" / "00000001.json"
    original = record.read_bytes()
    try:
        real_owner(record, 65533 if os.geteuid() != 65533 else 65532)
        with workspace.WorkspaceStore(root) as store:
            with pytest.raises(WorkspaceRefusal) as error:
                store.load()
            assert_refusal(error, "unsafe_path")
        assert record.read_bytes() == original
    finally:
        if record.stat().st_uid != os.geteuid():
            os.chown(record, os.geteuid(), -1)
    with workspace.WorkspaceStore(root) as store:
        assert store.load().seq == 1


@pytest.mark.parametrize("target,policy", [(target, policy) for target in ("workspace", "events", "event")
    for policy in ("foreign", "sticky_root") if target != "event" or policy != "sticky_root"])
def test_coordination_policy_rechecks_held_objects_before_read(tmp_path, monkeypatch, target, policy):
    root = make_store(tmp_path)
    path = {"workspace": root, "events": root / "events", "event": root / "events" / "00000001.json"}[target]
    info = path.stat()
    owned_os = workspace.os
    with workspace.WorkspaceStore(root) as store:
        assert store.load().seq == 1
        def foreign(info):
            if (info.st_dev, info.st_ino) == (path.stat().st_dev, path.stat().st_ino):
                return stat_observation(info, info.st_mode if policy == "foreign" else
                                        stat.S_IFMT(info.st_mode) | 0o1777,
                                        123456 if policy == "foreign" else 0)
            return info
        reads = []
        def record_read(*args):
            reads.append(args)
            return owned_os.read(*args)
        proxy = SimpleNamespace(**{**vars(owned_os), "fstat": lambda fd: foreign(owned_os.fstat(fd)),
                                  "read": record_read,
                                  "stat": lambda *a, **kw: foreign(owned_os.stat(*a, **kw))})
        monkeypatch.setattr(workspace, "os", proxy)
        with pytest.raises(WorkspaceRefusal) as error:
            store.load()
        assert_refusal(error, "unsafe_path")
        assert reads == []
        monkeypatch.setattr(workspace, "os", owned_os)
        assert store.load().seq == 1


def interpreter_command(root, body):
    """Carry only the existing ancestry observation seam into a fresh process."""
    observations = []
    for parent in root.parents:
        fd = os.open(parent, getattr(os, "O_PATH", os.O_RDONLY) | os.O_DIRECTORY)
        try:
            real, seen = os.fstat(fd), workspace.os.fstat(fd)
            if (real.st_uid, real.st_mode) != (seen.st_uid, seen.st_mode):
                observations.append([real.st_dev, real.st_ino, seen.st_uid, seen.st_mode])
        finally:
            os.close(fd)
    setup = '''
import json, os, sys
from pathlib import Path
from types import SimpleNamespace
from aegis_core import team_workspace_store as w
root = Path(sys.argv[1])
observations = {(dev, ino): (uid, mode) for dev, ino, uid, mode in json.loads(sys.argv[2])}
real_fstat = os.fstat
def fixture_info(fd):
    info = real_fstat(fd)
    if (info.st_dev, info.st_ino) in observations:
        uid, mode = observations[(info.st_dev, info.st_ino)]
        return SimpleNamespace(**{**{k: getattr(info, k) for k in dir(info) if k.startswith('st_')},
                                  'st_uid': uid, 'st_mode': mode})
    return info
w.os = SimpleNamespace(**{**vars(os), 'fstat': fixture_info})
'''
    return [sys.executable, "-c", setup + body, str(root), json.dumps(observations)]


@pytest.mark.parametrize("marker_failure", [False, True])
def test_committed_cleanup_is_recoverable_from_fresh_interpreter(tmp_path, marker_failure):
    if sys.platform != "linux":
        pytest.skip("kernel pid/start-time identity requires Linux proc")
    root = make_store(tmp_path, [event(1, "init", LIMITS), event(2, "register", INITIATIVE),
                               event(3, "request", _request_data())])
    writer = "fail_marker = " + repr(marker_failure) + "\n" + '''
def fail_marker_seek(*args):
    raise OSError('marker write failed')
def fail_release(name, **kw):
    if name == '.write.lock':
        if fail_marker:
            w.os.lseek = fail_marker_seek
        raise OSError('password=hunter2')
    return os.unlink(name, **kw)
w.os.unlink = fail_release
with w.WorkspaceStore(root) as store:
    print(json.dumps(w.grant_next(store, 'writer')))
'''
    result = subprocess.run(interpreter_command(root, writer), capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    code, answer = json.loads(result.stdout)
    assert code == 0 and answer["granted"]["state"] == "granted"
    assert answer["warnings"][0]["reason"] == "lock_release"
    assert json.loads((root / ".write.lock").read_bytes())["released"] == (0 if marker_failure else 1)
    reader = '''
with w.WorkspaceStore(root) as store:
    with store.lock():
        assert store.load().seq == 4
        store.append(store.load(), 'set_limits', {'source': 'retry', 'writer_limit': 4})
    print(store.load().seq)
'''
    result = subprocess.run(interpreter_command(root, reader), capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "5"
    assert not (root / ".write.lock").exists()


def test_fresh_interpreter_excludes_live_writer_before_and_after_cleanup_failure(tmp_path, monkeypatch):
    if sys.platform != "linux":
        pytest.skip("kernel pid/start-time identity requires Linux proc")
    root = make_store(tmp_path)
    owned_os = workspace.os
    def fail_release(name, **kw):
        if name == ".write.lock":
            raise OSError("cleanup failed")
        return os.unlink(name, **kw)
    contender = '''
with w.WorkspaceStore(root) as store:
    try:
        with store.lock():
            raise AssertionError('live writer was removed')
    except w.WorkspaceRefusal as error:
        print(error.reason)
'''
    def assert_busy():
        result = subprocess.run(interpreter_command(root, contender), capture_output=True, text=True, timeout=15)
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "busy"
    with workspace.WorkspaceStore(root) as store:
        with store.lock():
            store.append(store.load(), "register", INITIATIVE)
            assert_busy()
            before = json.loads((root / ".write.lock").read_bytes())
            assert before["released"] == 0 and before["identity"]["pid"] == os.getpid()
            monkeypatch.setattr(workspace, "os", SimpleNamespace(**{**vars(owned_os), "unlink": fail_release}))
        monkeypatch.setattr(workspace, "os", owned_os)
        after = json.loads((root / ".write.lock").read_bytes())
        assert after == {**before, "released": 1}
        assert_busy()
        with store.lock():
            assert store.load().seq == 2
    assert not (root / ".write.lock").exists()


@pytest.mark.parametrize("field,value", [("dev", -1), ("ino", -1), ("grant_id", "bad"),
                                       ("released", 2), ("pid", []), ("identity", None)])
def test_durable_recovery_refuses_invalid_identity_then_retries(tmp_path, monkeypatch, field, value):
    root = make_store(tmp_path)
    owned_os = workspace.os
    def fail_release(name, **kw):
        if name == ".write.lock":
            raise OSError("cleanup failed")
        return os.unlink(name, **kw)
    with workspace.WorkspaceStore(root) as store:
        with store.lock():
            store.append(store.load(), "register", INITIATIVE)
            monkeypatch.setattr(workspace, "os", SimpleNamespace(**{**vars(owned_os), "unlink": fail_release}))
        monkeypatch.setattr(workspace, "os", owned_os)
        path = root / ".write.lock"
        good = path.read_bytes()
        record = json.loads(good)
        # Exercise cross-process recovery validation without needing a live foreign PID.
        record["pid"] = 2147483647
        if type(record["identity"]) is dict:
            record["identity"]["pid"] = record["pid"]
        record[field] = value
        raw = workspace.encoded(record)
        path.write_bytes(raw)
        with pytest.raises(WorkspaceRefusal) as error:
            with store.lock():
                pytest.fail("invalid recovery witness was accepted")
        assert_refusal(error, "busy")
        assert path.read_bytes() == raw and store.load().seq == 2
        path.write_bytes(good)
        manual_recovery_if_identity_unavailable(root)
        with store.lock():
            assert store.load().seq == 2


@pytest.mark.parametrize("phase", ["before_stat", "during_read", "before_recheck"])
def test_changing_lock_record_is_busy_and_retry_succeeds(tmp_path, monkeypatch, phase):
    root = make_store(tmp_path)
    owned_os = workspace.os
    def fail_release(name, **kw):
        if name == ".write.lock":
            raise OSError("cleanup failed")
        return os.unlink(name, **kw)
    with workspace.WorkspaceStore(root) as store:
        with store.lock():
            store.append(store.load(), "register", INITIATIVE)
            monkeypatch.setattr(workspace, "os", SimpleNamespace(**{**vars(owned_os), "unlink": fail_release}))
        monkeypatch.setattr(workspace, "os", owned_os)
        path, touched = root / ".write.lock", []
        def changing_read(fd, size):
            raw = owned_os.read(fd, size)
            if phase == "during_read" and owned_os.fstat(fd).st_ino == path.stat().st_ino and not touched:
                info = path.stat()
                os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns + 1))
                touched.append(True)
            return raw
        stats = []
        def disappearing_stat(name, **kw):
            if name == ".write.lock":
                stats.append(name)
                if len(stats) == {"before_stat": 1, "during_read": 0, "before_recheck": 3}[phase]:
                    path.unlink()
            return owned_os.stat(name, **kw)
        monkeypatch.setattr(workspace, "os", SimpleNamespace(**{**vars(owned_os), "read": changing_read,
                                                              "stat": disappearing_stat}))
        with pytest.raises(WorkspaceRefusal) as error:
            with store.lock():
                pytest.fail("changing lock identity was accepted")
        assert_refusal(error, "busy")
        monkeypatch.setattr(workspace, "os", owned_os)
        manual_recovery_if_identity_unavailable(root)
        with store.lock():
            assert store.load().seq == 2


def test_concurrent_fresh_interpreters_recover_without_duplicate_publication(tmp_path):
    if sys.platform != "linux":
        pytest.skip("kernel pid/start-time identity requires Linux proc")
    root = make_store(tmp_path)
    writer = '''
def fail_release(name, **kw):
    if name == '.write.lock':
        raise OSError('cleanup failed')
    return os.unlink(name, **kw)
w.os.unlink = fail_release
with w.WorkspaceStore(root) as store:
    with store.lock():
        store.append(store.load(), 'set_limits', {'source': 'writer', 'writer_limit': 4})
'''
    result = subprocess.run(interpreter_command(root, writer), capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    contender = '''
with w.WorkspaceStore(root) as store:
    try:
        with store.lock():
            store.append(store.load(), 'set_limits', {'source': 'contender', 'writer_limit': 3})
        print('committed')
    except w.WorkspaceRefusal as error:
        assert error.reason == 'busy'
        print('busy')
'''
    command = interpreter_command(root, contender)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(subprocess.run, command, capture_output=True, text=True, timeout=15) for _ in range(2)]
        results = [future.result(timeout=20) for future in futures]
    assert all(result.returncode == 0 for result in results), [result.stderr for result in results]
    committed = sum(result.stdout.strip() == "committed" for result in results)
    assert committed >= 1
    with workspace.WorkspaceStore(root) as store, store.lock():
        assert store.load().seq == 2 + committed
        store.append(store.load(), "set_limits", {"source": "retry", "writer_limit": 2})
        assert store.load().seq == 3 + committed


@pytest.mark.parametrize("mode", [0o755, 0o711, 0o1777])
def test_evidence_directly_under_trusted_root_parent_keeps_legacy_success(tmp_path, monkeypatch, mode):
    root = make_store(tmp_path)
    parent = root / "shared-evidence"
    parent.mkdir(mode=0o700)
    proof = parent / "proof"
    proof.write_bytes(b"proof")
    reference = {"path": str(proof), "sha256": hashlib.sha256(b"proof").hexdigest()}
    parent.chmod(mode)
    target = parent.stat()
    owned_os = workspace.os
    def trusted_parent(fd):
        info = owned_os.fstat(fd)
        if (info.st_dev, info.st_ino) == (target.st_dev, target.st_ino):
            return stat_observation(info, info.st_mode, 0)
        return info
    monkeypatch.setattr(workspace, "os", SimpleNamespace(**{**vars(owned_os), "fstat": trusted_parent}))
    assert legacy.verify_evidence(reference) is None
    assert workspace.verify_evidence(reference) is None
    # A traversal-only evidence parent does not acquire coordination authority.
    if os.geteuid() != 0 or mode == 0o1777:
        with pytest.raises(WorkspaceRefusal) as error:
            workspace.WorkspaceStore(parent)
        assert_refusal(error, "unsafe_path")


@pytest.mark.parametrize("identity_mode", ["observation_failure", "unsupported", "absent"])
def test_unknown_identity_keeps_fresh_process_legacy_manual_recovery(tmp_path, identity_mode):
    root = make_store(tmp_path, [event(1, "init", LIMITS), event(2, "register", INITIATIVE),
                               event(3, "request", _request_data())])
    writer = "identity_mode = " + repr(identity_mode) + "\n" + '''
from aegis_core import kernel_identity as kernel
def unavailable(pid):
    if identity_mode == 'absent':
        return None
    raise kernel.IdentityError('unavailable' if identity_mode == 'observation_failure' else 'unsupported')
def fail_release(name, **kw):
    if name == '.write.lock':
        raise OSError('password=hunter2')
    return os.unlink(name, **kw)
w._kernel = SimpleNamespace(**{**vars(kernel), 'process_identity': unavailable,
    'descriptor_supported': (lambda: False) if identity_mode == 'unsupported' else kernel.descriptor_supported})
w.os.unlink = fail_release
with w.WorkspaceStore(root) as store:
    code, result = w.grant_next(store, 'writer')
    assert code == 0 and result['granted']['state'] == 'granted'
    assert result['warnings'][0]['reason'] == 'lock_release'
    assert 'hunter2' not in repr(result)
    raw = (root / '.write.lock').read_bytes()
    assert json.loads(raw)['identity'] == 'unavailable'
    try:
        with store.lock():
            raise AssertionError('unknown same-PID identity was automatically recovered')
    except w.WorkspaceRefusal as error:
        assert error.reason == 'busy'
    assert (root / '.write.lock').read_bytes() == raw
    print(json.dumps(result))
'''
    result = subprocess.run(interpreter_command(root, writer), capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["granted"]["state"] == "granted"
    before = (root / ".write.lock").read_bytes()
    reader = '''
from tools import hierarchy_workspace as old
raw = (root / '.write.lock').read_bytes()
assert json.loads(raw)['identity'] == 'unavailable'
with w.WorkspaceStore(root) as store:
    for attempt in range(2):
        try:
            with store.lock():
                raise AssertionError('unknown identity was automatically recovered')
        except w.WorkspaceRefusal as error:
            assert error.reason == 'busy' and error.code == 1
            assert 'inspect an abandoned lock' in error.next_action
        assert (root / '.write.lock').read_bytes() == raw
    try:
        with old.Store(root).lock():
            raise AssertionError('legacy accepted the abandoned lock')
    except ValueError as error:
        assert str(error) == 'workspace store is busy; inspect an abandoned lock before retrying'
    assert store.load().seq == 4
    # The trusted owner has inspected the exited writer and performs legacy manual recovery.
    (root / '.write.lock').unlink()
    with store.lock():
        store.append(store.load(), 'set_limits', {'source': 'manual-retry', 'writer_limit': 4})
    assert store.load().seq == 5
print('manual recovery succeeded')
'''
    result = subprocess.run(interpreter_command(root, reader), capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "manual recovery succeeded"
    assert json.loads(before)["identity"] == "unavailable"
    assert not (root / ".write.lock").exists()


def test_grant_cleanup_warning_belongs_only_to_its_call(tmp_path, monkeypatch):
    root = make_store(tmp_path, [event(1, "init", LIMITS), event(2, "register", INITIATIVE),
                               event(3, "request", _request_data())])
    owned_os, failures = workspace.os, []
    def fail_first_release(name, **kw):
        if name == ".write.lock" and not failures:
            failures.append(True)
            raise OSError("password=hunter2")
        return owned_os.unlink(name, **kw)
    monkeypatch.setattr(workspace, "os", SimpleNamespace(**{**vars(owned_os), "unlink": fail_first_release}))
    with workspace.WorkspaceStore(root) as store:
        first_code, first = workspace.grant_next(store, "writer")
        assert first_code == 0 and first["granted"]["state"] == "granted"
        validate_warnings(first["warnings"])
        assert first["warnings"][0]["reason"] == "lock_release"
        assert "hunter2" not in repr(first)
        manual_recovery_if_identity_unavailable(root)
        clean = workspace.grant_next(store, "writer")
        expected = legacy.grant_next(legacy.Store(root), "writer")
        assert clean == expected
        assert clean[0] == 3 and clean[1]["reason"] == "queue_empty"
        assert "warnings" not in clean[1]
        assert clean[1].get("next_action") == expected[1].get("next_action")
        assert first["warnings"][0]["reason"] == "lock_release"
        assert store.load().seq == 4
    assert not (root / ".write.lock").exists()


@pytest.mark.parametrize("operation", ["append", "publish", "uncommitted"])
def test_raw_lock_cleanup_warning_does_not_leak_to_later_grant(tmp_path, monkeypatch, operation):
    root = make_store(tmp_path, [event(1, "init", LIMITS), event(2, "register", INITIATIVE),
                               event(3, "request", _request_data())])
    owned_os, failures = workspace.os, []
    def fail_first_release(name, **kw):
        if name == ".write.lock" and not failures:
            failures.append(True)
            raise OSError("password=hunter2")
        return owned_os.unlink(name, **kw)
    monkeypatch.setattr(workspace, "os", SimpleNamespace(**{**vars(owned_os), "unlink": fail_first_release}))
    with workspace.WorkspaceStore(root) as store:
        def call():
            with store.lock():
                data = {"source": "call-a", "writer_limit": 4}
                if operation == "append":
                    store.append(store.load(), "set_limits", data)
                elif operation == "publish":
                    store.publish("00000004.json", workspace.encoded(event(4, "set_limits", data)))
        if operation == "uncommitted":
            with pytest.raises(WorkspaceRefusal) as error:
                call()
            assert_refusal(error, "io")
        else:
            call()
        manual_recovery_if_identity_unavailable(root)
        code, result = workspace.grant_next(store, "writer")
        assert code == 0 and result["granted"]["state"] == "granted"
        assert "warnings" not in result
        assert "hunter2" not in repr(result)
        assert store.load().seq == (4 if operation == "uncommitted" else 5)
        clean = workspace.grant_next(store, "writer")
        assert clean == legacy.grant_next(legacy.Store(root), "writer")
        assert "warnings" not in clean[1]
    assert not (root / ".write.lock").exists()


def test_two_threads_on_one_store_own_their_cleanup_warning(tmp_path, monkeypatch):
    root = make_store(tmp_path, [event(1, "init", LIMITS), event(2, "register", INITIATIVE),
                               event(3, "request", _request_data())])
    owned_os, roles = workspace.os, local()
    failed_identity = []
    failed_release, resume = Event(), Event()
    def fail_one_thread(name, **kw):
        if name == ".write.lock" and getattr(roles, "name", None) == "failing" and not failed_identity:
            info = owned_os.stat(name, follow_symlinks=False, **kw)
            failed_identity.append((info.st_dev, info.st_ino))
            raise OSError("password=hunter2")
        return owned_os.unlink(name, **kw)
    def pause_after_close(fd):
        info = owned_os.fstat(fd)
        owned_os.close(fd)
        if (getattr(roles, "name", None) == "failing" and
                (info.st_dev, info.st_ino) in failed_identity and not failed_release.is_set()):
            failed_release.set()
            assert resume.wait(10)
    proxy = SimpleNamespace(**{**vars(owned_os), "unlink": fail_one_thread, "close": pause_after_close})
    monkeypatch.setattr(workspace, "os", proxy)
    with workspace.WorkspaceStore(root) as store:
        def grant(role):
            roles.name = role
            return workspace.grant_next(store, "writer")
        with ThreadPoolExecutor(max_workers=2) as pool:
            failing = pool.submit(grant, "failing")
            try:
                assert failed_release.wait(10)
                manual_recovery_if_identity_unavailable(root)
                clean = pool.submit(grant, "clean").result(timeout=10)
                assert clean == legacy.grant_next(legacy.Store(root), "writer")
                assert "warnings" not in clean[1]
            finally:
                resume.set()
            code, result = failing.result(timeout=10)
        assert code == 0 and result["granted"]["state"] == "granted"
        validate_warnings(result["warnings"])
        assert result["warnings"][0]["reason"] == "lock_release"
        assert "hunter2" not in repr(result)
        assert store.load().seq == 4
    assert not (root / ".write.lock").exists()
