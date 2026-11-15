"""Public starter matrix; owner commands and kernel/process boundaries only."""
import copy
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import errno
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from types import SimpleNamespace

import pytest

from aegis_core import team_profile, team_supervisor
from aegis_core import team_supervisor_start as module


def starter():
    return module


def make_store(tmp_path):
    if not module.descriptor_supported():
        pytest.skip("requires Linux process identity and anchored descriptors")
    root = tmp_path.resolve()
    config = root / ".config" / "aegis"
    config.mkdir(parents=True, mode=0o700)
    config.chmod(0o700)
    return root, config


def symlink_or_skip(link, target, directory=False):
    try:
        link.symlink_to(target, target_is_directory=directory)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")


def enabled(pauses=()):
    return team_profile.resolve(user={"supervisor": {
        "components": {"writer": {"enabled": True}}, "pauses": list(pauses),
    }})["profile"]


def fake_process(monkeypatch, *, failure=None):
    calls = []

    def spawn(argv, **kwargs):
        calls.append((argv, kwargs))
        if failure is not None:
            raise failure
        return SimpleNamespace(pid=1234, poll=lambda: None, kill=lambda: None, wait=lambda **kw: 0)

    monkeypatch.setattr(module, "subprocess", SimpleNamespace(**{
        **vars(subprocess), "Popen": spawn,
    }))
    monkeypatch.setattr(module, "process_identity", lambda pid: {"pid": pid, "start_ticks": 77})
    return calls


def run(candidate, root, body=None, now=0, **kwargs):
    return candidate.start(enabled() if body is None else body,
                        {"writer": [sys.executable, "-c", "pass"]},
                        user_root=root, now=now, **kwargs)


@pytest.mark.parametrize("case", ["refused", "empty", "false_row"])
def test_only_start_entries_with_would_start_act(tmp_path, monkeypatch, case):
    root, config = make_store(tmp_path)
    calls = fake_process(monkeypatch)
    body = enabled()
    if case == "refused":
        body = {}
    elif case == "empty":
        body = team_profile.resolve()["profile"]
    else:
        original = team_supervisor.plan

        def plan(*args):
            value = original(*args)
            for row in value["components"]:
                row["action"] = "disabled"
            return value

        monkeypatch.setattr(module, "plan", plan)
    before = copy.deepcopy(body)
    for _ in range(2):
        result = run(module, root, body)
        assert result["attempts"] == []
    assert not calls and body == before
    assert list(config.iterdir()) == []


def test_success_records_identity_and_prevents_duplicate(tmp_path, monkeypatch):
    root, config = make_store(tmp_path)
    calls = fake_process(monkeypatch)
    first = run(module, root)
    assert first["attempts"] == [{"id": "writer", "outcome": "started"}]
    record = json.loads((config / module.PROCESSES_NAME).read_text())
    identity = record["processes"]["writer"]
    assert record["version"] == 2
    assert identity["pid"] == 1234 and identity["start_ticks"] == 77
    assert len(identity["boot_id"]) == 36
    assert identity["pid_namespace"] == os.readlink("/proc/self/ns/pid")
    assert team_supervisor.load_state(root)["components"]["writer"]["failures"] == []
    assert run(module, root)["attempts"] == []
    assert len(calls) == 1


def test_pid_reuse_is_dead_and_restarts(tmp_path, monkeypatch):
    root, config = make_store(tmp_path)
    calls = fake_process(monkeypatch)
    assert run(module, root)["status"] == "ok"
    monkeypatch.setattr(module, "process_identity", lambda pid: {"pid": pid, "start_ticks": 88})
    assert run(module, root)["attempts"] == [{"id": "writer", "outcome": "started"}]
    assert len(calls) == 2
    assert json.loads((config / module.PROCESSES_NAME).read_text())["processes"]["writer"]["start_ticks"] == 88


@pytest.mark.parametrize("failure", [FileNotFoundError(errno.ENOENT, "SECRET", sys.executable),
    PermissionError(errno.EACCES, "SECRET", sys.executable), OSError(errno.ENOEXEC, "SECRET", sys.executable),
    NotADirectoryError(errno.ENOTDIR, "SECRET", sys.executable)])
def test_failed_start_records_backoff_then_retries(tmp_path, monkeypatch, failure):
    root, _ = make_store(tmp_path)
    calls = fake_process(monkeypatch, failure=failure)
    first = run(module, root)
    assert first["attempts"] == [{"id": "writer", "outcome": "start_failed"}]
    assert "SECRET" not in repr(first)
    assert team_supervisor.load_state(root)["components"]["writer"]["failures"] == [0]
    assert run(module, root, now=59)["attempts"] == []
    assert len(calls) == 1
    assert run(module, root, now=60)["attempts"] == first["attempts"]
    assert len(calls) == 2


@pytest.mark.parametrize("pause", team_supervisor.PAUSES)
def test_typed_pauses_are_never_changed(tmp_path, monkeypatch, pause):
    root, config = make_store(tmp_path)
    calls = fake_process(monkeypatch)
    body = enabled([pause])
    path = config / "team.json"
    frozen = json.dumps(body).encode()
    path.write_bytes(frozen)
    before = copy.deepcopy(body)
    run(module, root, body)
    run(module, root, body)
    if pause in ("owner", "capacity", "disk", "audit", "writer"):
        assert not calls
    assert path.read_bytes() == frozen and body == before


@pytest.mark.parametrize("defect", ["oversized", "symlink", "mode", "malformed", "deep", "duplicate", "unreadable"])
def test_bad_state_refuses_before_spawn(tmp_path, monkeypatch, defect):
    root, config = make_store(tmp_path)
    calls = fake_process(monkeypatch)
    target = config / team_supervisor.STATE_NAME
    data = json.dumps(team_supervisor.empty_state()).encode()
    if defect == "symlink":
        outside = tmp_path / "outside"
        outside.write_bytes(data)
        symlink_or_skip(target, outside)
    else:
        data = {"oversized": b" " * 131073, "malformed": b"{", "deep": b"[" * 10000,
                "duplicate": b'{"version":1,"version":1}', "mode": data, "unreadable": data}[defect]
        target.write_bytes(data)
        if defect == "mode":
            target.chmod(0o666)
        if defect == "unreadable":
            def deny(*args, **kwargs):
                raise PermissionError("SECRET")
            monkeypatch.setattr(module, "read_owned_leaf", deny)
    for _ in range(2):
        result = run(module, root)
        assert result == {"status": "refused", "code": "state_unavailable",
                          "reason": "unsafe or unreadable supervisor state", "attempts": []}
    assert not calls and target.read_bytes() == data


def test_concurrent_starters_never_double_start(tmp_path, monkeypatch):
    root, _ = make_store(tmp_path)
    calls = fake_process(monkeypatch)
    gate = threading.Barrier(2)

    def invoke():
        gate.wait(timeout=3)
        return run(module, root)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: invoke(), range(2)))
    assert len(calls) == 1
    assert sum(len(row["attempts"]) for row in results) == 1


def test_repository_swap_cannot_change_liveness_or_state(tmp_path, monkeypatch):
    root, config = make_store(tmp_path)
    calls = fake_process(monkeypatch)
    repo, other = tmp_path / "repo", tmp_path / "other"
    repo.mkdir()
    other.mkdir()
    run(module, root)
    frozen = {p.name: p.read_bytes() for p in config.iterdir()}
    repo.rename(tmp_path / "old-repo")
    symlink_or_skip(repo, other, True)
    assert run(module, root)["attempts"] == []
    assert len(calls) == 1
    assert frozen == {p.name: p.read_bytes() for p in config.iterdir()}


def test_unsupported_platform_refuses_without_io(tmp_path, monkeypatch):
    monkeypatch.setattr(module, "descriptor_supported", lambda: False)
    assert run(module, tmp_path)["code"] == "unsupported_platform"
    assert not list(tmp_path.iterdir())


def test_real_process_identity_and_start(tmp_path):
    root, _ = make_store(tmp_path)
    assert module.process_identity(os.getpid())["pid"] == os.getpid()
    result = module.start(enabled(), {"writer": [sys.executable, "-c", "import time; time.sleep(15)"]},
                          user_root=root, now=0)
    assert result["attempts"] == [{"id": "writer", "outcome": "started"}]
    record = json.loads((root / ".config" / "aegis" / module.PROCESSES_NAME).read_text())
    pid = record["processes"]["writer"]["pid"]
    try:
        assert run(module, root)["attempts"] == []
    finally:
        os.kill(pid, 15)
        os.waitpid(pid, 0)


@pytest.mark.parametrize("fail_at", [1, 2, 3, 4, 5])
def test_write_failure_never_blindly_reexecutes(tmp_path, monkeypatch, fail_at):
    root, _ = make_store(tmp_path)
    calls = fake_process(monkeypatch)
    boundary = module.storage_confined
    count = [0]

    class Publication:
        def __init__(self, directory, name):
            self.handle = boundary.ConfinedFile(directory, name)

        def publish_bytes(self, *args, **kwargs):
            count[0] += 1
            if count[0] == fail_at:
                raise OSError("SECRET")
            return self.handle.publish_bytes(*args, **kwargs)

    monkeypatch.setattr(module, "storage_confined", SimpleNamespace(**{
        **vars(boundary), "ConfinedFile": Publication,
    }))
    result = run(module, root)
    assert result["code"] == "state_unavailable" and "SECRET" not in repr(result)
    monkeypatch.setattr(module, "storage_confined", boundary)
    for _ in range(2):
        retry = run(module, root)
        if fail_at > 1:
            assert retry["code"] == "recovery_required"
    assert len(calls) == (0 if fail_at == 2 else 1)


@pytest.mark.parametrize("value", [[], {"version": True, "processes": {}, "pending": None},
    {"version": 2, "processes": {}, "pending": "bad"},
    {"version": 2, "processes": {"writer": {"pid": True, "start_ticks": 1}}, "pending": None},
    {"version": 2, "processes": {"writer": {"pid": 1234, "start_ticks": -1}}, "pending": None}])
def test_bad_identity_records_refuse_and_remain_unchanged(tmp_path, monkeypatch, value):
    root, config = make_store(tmp_path)
    calls = fake_process(monkeypatch)
    path = config / module.PROCESSES_NAME
    frozen = json.dumps(value).encode()
    path.write_bytes(frozen)
    for _ in range(2):
        assert run(module, root)["code"] == "state_unavailable"
    assert not calls and path.read_bytes() == frozen


def test_held_directory_survives_ancestor_swap(tmp_path, monkeypatch):
    root, config = make_store(tmp_path)
    calls = fake_process(monkeypatch)
    boundary = module.storage_confined
    old = root / "held-config"
    outside = root / "outside"
    outside.mkdir()
    switched = [False]

    class Publication:
        def __init__(self, directory, name):
            self.handle = boundary.ConfinedFile(directory, name)

        def publish_bytes(self, *args, **kwargs):
            if not switched[0]:
                switched[0] = True
                config.rename(old)
                symlink_or_skip(config, outside, True)
            return self.handle.publish_bytes(*args, **kwargs)

    monkeypatch.setattr(module, "storage_confined", SimpleNamespace(**{
        **vars(boundary), "ConfinedFile": Publication,
    }))
    assert run(module, root)["attempts"] == [{"id": "writer", "outcome": "started"}]
    assert len(calls) == 1 and not list(outside.iterdir())
    assert json.loads((old / team_supervisor.STATE_NAME).read_text())["version"] == 1
    assert run(module, root)["code"] == "state_unavailable"


@pytest.mark.parametrize("timeout", [0, -1, True, float("nan"), float("inf"), "SECRET"])
def test_bad_timeout_refuses_before_io(tmp_path, timeout):
    result = run(starter(), tmp_path, timeout=timeout)
    expected = "invalid_timeout" if starter().descriptor_supported() else "unsupported_platform"
    assert result["code"] == expected and "SECRET" not in repr(result)
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("commands", [[], {"bad": ["/bin/true"]}, {"writer": ["relative"]},
    {"writer": ["/absolute", "a" * 4097]}, {"writer": ["/absolute", "\0SECRET"]}])
def test_bad_commands_refuse_before_io(tmp_path, commands):
    result = starter().start(enabled(), commands, user_root=tmp_path, now=0)
    expected = "invalid_commands" if starter().descriptor_supported() else "unsupported_platform"
    assert result["code"] == expected and "SECRET" not in repr(result)
    assert not list(tmp_path.iterdir())


def test_identity_timeout_kills_and_reaps_child(tmp_path, monkeypatch):
    root, _ = make_store(tmp_path)
    real_identity = module.process_identity
    monkeypatch.setattr(module, "process_identity", lambda pid: real_identity(pid) if pid == os.getpid() else None)
    result = module.start(enabled(), {"writer": [sys.executable, "-c", "import time; time.sleep(15)"]},
                          user_root=root, now=0, timeout=0.05)
    assert result["attempts"] == [{"id": "writer", "outcome": "start_failed"}]
    assert run(module, root, now=1)["attempts"] == []


def test_unreadable_live_identity_is_not_treated_as_dead(tmp_path, monkeypatch):
    root, _ = make_store(tmp_path)
    original_identity = module.process_identity
    calls = fake_process(monkeypatch)
    run(module, root)
    boundary = module.storage_confined

    def deny(root, parts, **kwargs):
        if parts[-1] == "stat" and parts[0] != str(os.getpid()):
            raise boundary.ConfinedFileError("io")
        return boundary.confined_file(root, parts, **kwargs)

    monkeypatch.setattr(module, "process_identity", original_identity)
    monkeypatch.setattr(module, "storage_confined", SimpleNamespace(**{
        **vars(boundary), "confined_file": deny,
    }))
    assert run(module, root)["code"] == "identity_unavailable"
    assert len(calls) == 1


def test_success_clears_previous_failures(tmp_path, monkeypatch):
    root, _ = make_store(tmp_path)
    fake_process(monkeypatch, failure=FileNotFoundError(errno.ENOENT, "exec failed", sys.executable))
    run(module, root)
    fake_process(monkeypatch)
    assert run(module, root, now=60)["attempts"] == [{"id": "writer", "outcome": "started"}]
    slot = team_supervisor.load_state(root)["components"]["writer"]
    assert slot == {"delay_s": 30, "failures": []}


def test_real_exec_error_records_failure(tmp_path):
    root, _ = make_store(tmp_path)
    result = module.start(enabled(), {"writer": [str(root / "missing-program")]}, user_root=root, now=0)
    assert result["attempts"] == [{"id": "writer", "outcome": "start_failed"}]
    assert team_supervisor.load_state(root)["components"]["writer"]["failures"] == [0]


@pytest.mark.parametrize("failure", ["before_acquire", "after_acquire", "parent_stat"])
def test_state_helper_failure_closes_borrowed_descriptor(tmp_path, monkeypatch, failure):
    root, config = make_store(tmp_path)
    acquired = []
    boundary = module.storage_confined

    def unavailable():
        raise OSError("SECRET")

    @contextmanager
    def confined(root, parts, **kwargs):
        if failure == "before_acquire":
            raise boundary.ConfinedFileError("io")
        with boundary.confined_file(root, parts, **kwargs) as handle:
            acquired.append(handle._parent)
            if failure == "after_acquire":
                raise boundary.ConfinedFileError("io")
            yield SimpleNamespace(_parent=handle._parent, parent_stat=unavailable)

    monkeypatch.setattr(module, "storage_confined", SimpleNamespace(**{
        **vars(boundary), "confined_file": confined,
    }))
    assert run(module, root)["code"] == "state_unavailable"
    assert not list(config.iterdir())
    for fd in acquired:
        with pytest.raises(OSError) as refused:
            os.fstat(fd)
        assert refused.value.errno == errno.EBADF


def test_later_invocation_reaps_its_exited_child(tmp_path):
    root, config = make_store(tmp_path)
    result = module.start(enabled(), {"writer": [sys.executable, "-c", "import time; time.sleep(0.2)"]},
                          user_root=root, now=0)
    assert result["attempts"] == [{"id": "writer", "outcome": "started"}]
    pid = json.loads((config / module.PROCESSES_NAME).read_text())["processes"]["writer"]["pid"]
    try:
        deadline = time.monotonic() + 3
        while os.waitid(os.P_PID, pid, os.WEXITED | os.WNOWAIT | os.WNOHANG) is None:
            assert time.monotonic() < deadline, "child did not exit"
            time.sleep(0.01)
        assert run(module, root, enabled(["owner"]))["attempts"] == []
        with pytest.raises(ChildProcessError):
            os.waitpid(pid, os.WNOHANG)
    finally:
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass


@pytest.mark.parametrize("defect", ["array", "string", "nodes"])
def test_structural_limits_refuse_before_json_tree_allocation(tmp_path, monkeypatch, defect):
    root, config = make_store(tmp_path)
    state = team_supervisor.empty_state()
    if defect == "array":
        state["components"]["writer"]["failures"] = [0] * 101
    elif defect == "string":
        state["x" * 65] = 1
    else:
        state = {str(index): [0] * 100 for index in range(6)}
    frozen = json.dumps(state).encode()
    path = config / team_supervisor.STATE_NAME
    path.write_bytes(frozen)
    parsed = []

    def observe(*args, **kwargs):
        parsed.append(True)
        return json.loads(*args, **kwargs)

    monkeypatch.setattr(module, "json", SimpleNamespace(**{**vars(json), "loads": observe}))
    assert run(module, root)["code"] == "state_unavailable"
    assert parsed == [] and path.read_bytes() == frozen


def scope_sources(monkeypatch):
    values = {"boot": "12345678-1234-1234-1234-123456789abc", "namespace": "pid:[12345]"}
    boundary = module.storage_confined

    class BootFile:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read_bytes(self, maximum):
            if values["boot"] is None:
                raise boundary.ConfinedFileError("io")
            return (values["boot"] + "\n").encode("ascii")

    def confined(root, parts, **kwargs):
        if tuple(parts) == ("sys", "kernel", "random", "boot_id"):
            return BootFile()
        return boundary.confined_file(root, parts, **kwargs)

    def readlink(path, **kwargs):
        if path == "pid":
            if values["namespace"] is None:
                raise OSError("SECRET")
            return values["namespace"]
        return os.readlink(path, **kwargs)

    monkeypatch.setattr(module, "storage_confined", SimpleNamespace(**{
        **vars(boundary), "confined_file": confined,
    }))
    monkeypatch.setattr(module, "os", SimpleNamespace(**{**vars(os), "readlink": readlink}))
    return values


def test_namespace_change_is_ambiguous_and_never_duplicates(tmp_path, monkeypatch):
    root, config = make_store(tmp_path)
    calls = fake_process(monkeypatch)
    scope = scope_sources(monkeypatch)
    assert run(module, root)["attempts"] == [{"id": "writer", "outcome": "started"}]
    frozen = {p.name: p.read_bytes() for p in config.iterdir()}
    scope["namespace"] = "pid:[54321]"
    for _ in range(2):
        refused = run(module, root)
        assert refused["code"] == "identity_ambiguous"
        assert refused["reason"] == "supervisor process identity scope is ambiguous"
    assert len(calls) == 1 and frozen == {p.name: p.read_bytes() for p in config.iterdir()}


def test_previous_boot_is_dead_and_record_is_replaced(tmp_path, monkeypatch):
    root, config = make_store(tmp_path)
    calls = fake_process(monkeypatch)
    scope = scope_sources(monkeypatch)
    run(module, root)
    scope["boot"] = "abcdefab-1234-1234-1234-123456789abc"
    scope["namespace"] = "pid:[54321]"
    assert run(module, root)["attempts"] == [{"id": "writer", "outcome": "started"}]
    record = json.loads((config / module.PROCESSES_NAME).read_text())
    assert record["version"] == 2
    assert record["processes"]["writer"] == {
        "pid": 1234, "start_ticks": 77, "boot_id": scope["boot"], "pid_namespace": scope["namespace"],
    }
    assert run(module, root)["attempts"] == [] and len(calls) == 2


@pytest.mark.parametrize("source", ["boot", "namespace"])
@pytest.mark.parametrize("existing", [False, True])
def test_unavailable_identity_scope_refuses_without_writes(tmp_path, monkeypatch, source, existing):
    root, config = make_store(tmp_path)
    calls = fake_process(monkeypatch)
    scope = scope_sources(monkeypatch)
    if existing:
        run(module, root)
    frozen = {p.name: p.read_bytes() for p in config.iterdir()}
    scope[source] = None
    for _ in range(2):
        refused = run(module, root)
        assert refused["code"] == "identity_unavailable" and "SECRET" not in repr(refused)
    assert len(calls) == int(existing)
    assert frozen == {p.name: p.read_bytes() for p in config.iterdir()}


def test_old_unscoped_record_is_ambiguous_until_reconciled(tmp_path, monkeypatch):
    root, config = make_store(tmp_path)
    calls = fake_process(monkeypatch)
    path = config / module.PROCESSES_NAME
    frozen = json.dumps({"version": 1, "processes": {"writer": {"pid": 1234, "start_ticks": 77}},
                         "pending": None}).encode()
    path.write_bytes(frozen)
    for _ in range(2):
        assert run(module, root)["code"] == "identity_ambiguous"
    assert path.read_bytes() == frozen and not calls


@pytest.mark.parametrize("argv", [["/\ud800"], ["/absolute", "\ud800"]])
@pytest.mark.parametrize("existing", [False, True])
def test_unencodable_argv_preserves_state_and_corrected_call_starts(tmp_path, monkeypatch, argv, existing):
    root, config = make_store(tmp_path)
    calls = fake_process(monkeypatch)
    if existing:
        team_supervisor.store_state(team_supervisor.empty_state(), root)
    frozen = {p.name: p.read_bytes() for p in config.iterdir()}
    for _ in range(2):
        result = module.start(enabled(), {"writer": argv}, user_root=root, now=0)
        assert result["code"] == "invalid_commands"
    assert frozen == {p.name: p.read_bytes() for p in config.iterdir()} and not calls
    assert run(module, root)["attempts"] == [{"id": "writer", "outcome": "started"}]
    assert len(calls) == 1


@pytest.mark.parametrize("failure", [RuntimeError("SECRET"), ValueError("SECRET"), TypeError("SECRET"),
    UnicodeEncodeError("utf-8", "\ud800", 0, 1, "SECRET"), OSError("SECRET"),
    subprocess.TimeoutExpired("SECRET", 1), OSError(999999, "SECRET", sys.executable)])
def test_unproved_constructor_failure_preserves_intent(tmp_path, monkeypatch, failure):
    root, config = make_store(tmp_path)
    calls = fake_process(monkeypatch, failure=failure)
    for clock in (0, 60, 120):
        result = run(module, root, now=clock)
        assert result["code"] == "recovery_required"
        assert "SECRET" not in repr(result)
        assert json.loads((config / module.PROCESSES_NAME).read_text())["pending"] == "writer"
    assert len(calls) == 1


@pytest.mark.parametrize("source,value", [
    ("boot", "x" * 1000), ("boot", "not-a-boot-id"),
    ("namespace", "pid:[" + "1" * 1000 + "]"), ("namespace", "pid:[not-a-number]"),
])
def test_malformed_scope_sources_refuse_without_allocating_state(tmp_path, monkeypatch, source, value):
    root, config = make_store(tmp_path)
    calls = fake_process(monkeypatch)
    scope = scope_sources(monkeypatch)
    scope[source] = value
    for _ in range(2):
        assert run(module, root)["code"] == "identity_unavailable"
    assert not calls and not list(config.iterdir())


@pytest.mark.parametrize("failure", ["proc_root", "namespace_parent", "namespace_link"])
def test_namespace_helper_failure_closes_borrowed_descriptors(tmp_path, monkeypatch, failure):
    root, config = make_store(tmp_path)
    calls = fake_process(monkeypatch)
    acquired = []
    boundary = module.storage_confined

    @contextmanager
    def confined(root, parts, **kwargs):
        with boundary.confined_file(root, parts, **kwargs) as handle:
            if parts[-1] in ("self", "pid"):
                acquired.append(handle._parent)
                if (failure == "proc_root" and parts == ("self",)
                        or failure == "namespace_parent" and parts[-1] == "pid"):
                    raise boundary.ConfinedFileError("io")
            yield handle

    def readlink(path, **kwargs):
        if failure == "namespace_link" and path == "pid":
            raise OSError("SECRET")
        return os.readlink(path, **kwargs)

    monkeypatch.setattr(module, "storage_confined", SimpleNamespace(**{
        **vars(boundary), "confined_file": confined,
    }))
    monkeypatch.setattr(module, "os", SimpleNamespace(**{**vars(os), "readlink": readlink}))
    result = run(module, root)
    assert result["code"] == "identity_unavailable" and "SECRET" not in repr(result)
    assert acquired and not calls and not list(config.iterdir())
    for fd in acquired:
        with pytest.raises(OSError) as refused:
            os.fstat(fd)
        assert refused.value.errno == errno.EBADF


def test_concurrent_namespace_mismatch_never_starts(tmp_path, monkeypatch):
    root, config = make_store(tmp_path)
    calls = fake_process(monkeypatch)
    scope = scope_sources(monkeypatch)
    run(module, root)
    scope["namespace"] = "pid:[54321]"
    frozen = {p.name: p.read_bytes() for p in config.iterdir()}
    gate = threading.Barrier(2)

    def invoke():
        gate.wait(timeout=3)
        return run(module, root)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: invoke(), range(2)))
    assert all(row["code"] in ("state_locked", "identity_ambiguous") for row in results)
    assert len(calls) == 1 and frozen == {p.name: p.read_bytes() for p in config.iterdir()}


def test_proc_mount_pid_view_mismatch_refuses(tmp_path, monkeypatch):
    root, config = make_store(tmp_path)
    calls = fake_process(monkeypatch)

    def mismatched_self(path, **kwargs):
        if path == "self":
            return "0"
        return os.readlink(path, **kwargs)

    monkeypatch.setattr(module, "os", SimpleNamespace(**{**vars(os), "readlink": mismatched_self}))
    assert run(module, root)["code"] == "identity_unavailable"
    assert not calls and not list(config.iterdir())


def test_failure_after_child_creation_retains_recovery_intent(tmp_path, monkeypatch):
    root, config = make_store(tmp_path)
    real_identity = module.process_identity
    calls = fake_process(monkeypatch)
    monkeypatch.setattr(module, "process_identity", real_identity)
    boundary = module.storage_confined

    def unreadable_stat(root, parts, **kwargs):
        if parts[-1] == "stat" and parts[0] != str(os.getpid()):
            raise boundary.ConfinedFileError("io")
        return boundary.confined_file(root, parts, **kwargs)

    monkeypatch.setattr(module, "storage_confined", SimpleNamespace(**{
        **vars(boundary), "confined_file": unreadable_stat,
    }))
    assert run(module, root)["code"] == "identity_unavailable"
    assert json.loads((config / module.PROCESSES_NAME).read_text())["pending"] == "writer"
    assert run(module, root)["code"] == "recovery_required" and len(calls) == 1


@pytest.mark.parametrize("failure", ["kill", "wait"])
@pytest.mark.parametrize("existing", [False, True])
def test_uncertain_cleanup_preserves_intent_and_process_record(tmp_path, monkeypatch, failure, existing):
    root, config = make_store(tmp_path)
    calls = fake_process(monkeypatch)
    if existing:
        run(module, root)
    previous = json.loads((config / module.PROCESSES_NAME).read_text())["processes"] if existing else {}

    def kill():
        if failure == "kill":
            raise OSError("SECRET")

    def wait(**kwargs):
        raise subprocess.TimeoutExpired("SECRET", 1)

    def spawn(*args, **kwargs):
        calls.append(True)
        return SimpleNamespace(pid=5678, poll=lambda: None, kill=kill, wait=wait)

    monkeypatch.setattr(module, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": spawn}))
    monkeypatch.setattr(module, "process_identity", lambda pid: (
        {"pid": pid, "start_ticks": 77} if pid == os.getpid() else None))
    result = run(module, root, timeout=0.01)
    assert result["code"] == "recovery_required" and "SECRET" not in repr(result)
    record = json.loads((config / module.PROCESSES_NAME).read_text())
    assert record["pending"] == "writer" and record["processes"] == previous
    for clock in (60, 120):
        assert run(module, root, now=clock)["code"] == "recovery_required"
    gate = threading.Barrier(2)

    def retry():
        gate.wait(timeout=3)
        return run(module, root, now=120)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: retry(), range(2)))
    assert all(row["code"] in ("state_locked", "recovery_required") for row in results)
    assert len(calls) == 1 + int(existing)


def test_missing_self_process_table_witness_refuses_before_spawn(tmp_path, monkeypatch):
    root, config = make_store(tmp_path)
    real_identity = module.process_identity
    calls = fake_process(monkeypatch)
    monkeypatch.setattr(module, "process_identity", real_identity)
    boundary = module.storage_confined

    def unavailable(root, parts, **kwargs):
        if parts[-1] == "stat":
            raise boundary.ConfinedFileError("missing")
        return boundary.confined_file(root, parts, **kwargs)

    monkeypatch.setattr(module, "storage_confined", SimpleNamespace(**{
        **vars(boundary), "confined_file": unavailable,
    }))
    for _ in range(2):
        assert run(module, root)["code"] == "identity_unavailable"
    gate = threading.Barrier(2)

    def retry():
        gate.wait(timeout=3)
        return run(module, root)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: retry(), range(2)))
    assert all(row["code"] in ("state_locked", "identity_unavailable") for row in results)
    assert not calls and not list(config.iterdir())


def test_starter_uses_confined_helpers_without_direct_opens(tmp_path, monkeypatch):
    root, _ = make_store(tmp_path)
    calls = fake_process(monkeypatch)

    def forbidden(*args, **kwargs):
        raise AssertionError("starter must borrow helper descriptors")

    monkeypatch.setattr(module, "os", SimpleNamespace(**{**vars(os), "open": forbidden}))
    assert run(module, root)["attempts"] == [{"id": "writer", "outcome": "started"}]
    assert len(calls) == 1


def test_concurrent_previous_boot_replacement_starts_once(tmp_path, monkeypatch):
    root, _ = make_store(tmp_path)
    calls = fake_process(monkeypatch)
    scope = scope_sources(monkeypatch)
    run(module, root)
    scope["boot"] = "abcdefab-1234-1234-1234-123456789abc"
    gate = threading.Barrier(2)

    def invoke():
        gate.wait(timeout=3)
        return run(module, root)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: invoke(), range(2)))
    assert sum(len(row["attempts"]) for row in results) == 1 and len(calls) == 2
    assert run(module, root)["attempts"] == []


def test_concurrent_bad_and_corrected_commands_start_once(tmp_path, monkeypatch):
    root, config = make_store(tmp_path)
    calls = fake_process(monkeypatch)
    gate = threading.Barrier(2)

    def bad():
        gate.wait(timeout=3)
        return module.start(enabled(), {"writer": ["/\ud800"]}, user_root=root, now=0)

    def good():
        gate.wait(timeout=3)
        return run(module, root)

    with ThreadPoolExecutor(max_workers=2) as pool:
        refused, started = pool.submit(bad), pool.submit(good)
        assert refused.result(timeout=3)["code"] == "invalid_commands"
        assert started.result(timeout=3)["attempts"] == [{"id": "writer", "outcome": "started"}]
    assert len(calls) == 1
    assert json.loads((config / module.PROCESSES_NAME).read_text())["pending"] is None


@pytest.mark.parametrize("failure", [MemoryError("SECRET"), KeyboardInterrupt("SECRET"),
    OSError(errno.EINTR, "SECRET"), OSError(errno.ENOENT, "SECRET", "/different-executable")])
@pytest.mark.parametrize("existing", [False, True])
def test_constructor_failure_after_real_child_keeps_custody(tmp_path, monkeypatch, failure, existing):
    root, config = make_store(tmp_path)
    real_identity = module.process_identity
    if existing:
        fake_process(monkeypatch)
        run(module, root)
    previous = json.loads((config / module.PROCESSES_NAME).read_text())["processes"] if existing else {}
    children = []

    def spawn(*args, **kwargs):
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"], **kwargs)
        children.append(child)
        raise failure

    monkeypatch.setattr(module, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": spawn}))
    monkeypatch.setattr(module, "process_identity", lambda pid: real_identity(pid) if pid == os.getpid() else None)
    try:
        if isinstance(failure, KeyboardInterrupt):
            with pytest.raises(KeyboardInterrupt, match="^SECRET$"):
                run(module, root)
        else:
            refused = run(module, root)
            assert refused["code"] == "recovery_required" and "SECRET" not in repr(refused)
        record = json.loads((config / module.PROCESSES_NAME).read_text())
        assert record["pending"] == "writer" and record["processes"] == previous
        for clock in (60, 120):
            assert run(module, root, now=clock)["code"] == "recovery_required"
        gate = threading.Barrier(2)

        def retry():
            gate.wait(timeout=3)
            return run(module, root, now=120)

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: retry(), range(2)))
        assert all(row["code"] in ("state_locked", "recovery_required") for row in results)
        assert len(children) == 1 and children[0].poll() is None
    finally:
        for child in children:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=3)


def test_installed_cpython_exec_error_is_reaped_before_refusal(tmp_path):
    root, _ = make_store(tmp_path)
    script = r'''
import errno, json, os, subprocess, sys
from pathlib import Path
from types import SimpleNamespace
from aegis_core import team_profile
from aegis_core import team_supervisor_start as starter
root = Path(sys.argv[1])
missing = str(root / "missing-executable")
errors = []
def observed(argv, **kwargs):
    try:
        return subprocess.Popen(argv, **kwargs)
    except OSError as error:
        errors.append({"errno": error.errno, "filename_matches": error.filename == missing})
        raise
starter.subprocess = SimpleNamespace(**{**vars(subprocess), "Popen": observed})
body = team_profile.resolve(user={"supervisor": {"components": {"writer": {"enabled": True}}}})["profile"]
results = [starter.start(body, {"writer": [missing]}, user_root=root, now=clock) for clock in (0, 60)]
try:
    os.waitpid(-1, os.WNOHANG)
except ChildProcessError:
    reaped = True
else:
    reaped = False
print(json.dumps({"errors": errors, "results": results, "reaped": reaped}))
'''
    child = subprocess.run([sys.executable, "-c", script, str(root)],
                           capture_output=True, text=True, timeout=10, check=True)
    observed = json.loads(child.stdout)
    assert observed["errors"] == [{"errno": errno.ENOENT, "filename_matches": True}] * 2
    assert observed["reaped"] is True
    assert observed["results"] == [{"status": "ok", "attempts": [{"id": "writer", "outcome": "start_failed"}]}] * 2
