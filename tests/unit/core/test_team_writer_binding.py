"""Owner-home writer bindings with shared capability-gated fixtures.

Lease fixtures use memory or disposable repositories. Nothing reads the product checkout's git
history. Descriptor, symlink, and mode cases skip when the platform cannot
support them. The unsupported path monkeypatches this module's
descriptor_supported and does not open a home.
"""
from __future__ import annotations

from contextlib import contextmanager, nullcontext
import errno
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import threading
from types import SimpleNamespace

import pytest

from aegis_core import kernel_identity, storage, storage_confined, team
from aegis_core import team_writer_binding as binding
from tests.conftest import symlink_or_skip
from tests.helpers_writer_binding import call_bind, lease, make_home, make_store, root_binding_case


def found(*leases, unreadable=()):
    return team.LeaseSet(tuple(leases), tuple(unreadable))


def use_leases(monkeypatch, value):
    def selected(workspace, lane):
        chosen = value.get(lane) if isinstance(value, team.LeaseSet) else value
        if not isinstance(chosen, team.Lease):
            raise binding._Refusal("lease_unavailable")
        return chosen

    monkeypatch.setattr(binding, "_selected_lease", selected)


def leaf(home):
    return home / ".config" / "aegis" / binding.NAME


def absent_pid():
    for candidate in (2147483647, 2147483646, 2147483001):
        try:
            os.kill(candidate, 0)
        except ProcessLookupError:
            return candidate
        except PermissionError:
            continue
    pytest.skip("no absent pid available")


def worst_document():
    """256 maximum-width records, the reader cap's defining document."""
    record = {
        "boot_id": "01234567-89ab-cdef-0123-456789abcdef",
        "claim_id": "a" * 16,
        "gen": 2 ** 53,
        "pid": 2147483647,
        "pid_namespace": "pid:[" + ("9" * 20) + "]",
        "start_ticks": 10 ** 20 - 1,
    }
    bindings = {("a" * 60) + "%03d" % index: record for index in range(256)}
    assert all(len(lane) == 63 for lane in bindings)
    return (json.dumps({"version": 1, "bindings": bindings}, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _refusal(code):
    return {"status": "refused", "code": code, "reason": binding._REASONS[code]}


def _opens(monkeypatch):
    opened = []

    @contextmanager
    def confined(*args, **kwargs):
        opened.append(args)
        yield SimpleNamespace()

    monkeypatch.setattr(binding, "_confined_file", confined)
    return opened


def test_reader_cap_matches_the_worst_case_document():
    data = worst_document()
    assert len(data) == 68379
    assert binding.MAX_BYTES == len(data)


def test_platform_without_nofollow_does_not_write(monkeypatch, tmp_path):
    opened = _opens(monkeypatch)
    monkeypatch.setattr(binding.storage_confined, "descriptor_supported", lambda: False)
    home = tmp_path / "zzmarker-home"
    result = binding.bind(str(home), str(tmp_path), "writer", 1)
    assert result == _refusal("unsupported_platform")
    assert opened == []
    assert not home.exists()


def test_descriptor_supported_false_does_not_open_a_home(monkeypatch, tmp_path):
    opened = _opens(monkeypatch)
    monkeypatch.setattr(binding, "descriptor_supported", lambda: False)
    home = tmp_path / "zzmarker-home"
    result = binding.bind(str(home), str(tmp_path), "writer", os.getpid())
    assert result == _refusal("unsupported_platform")
    assert opened == []
    assert not home.exists()


@pytest.mark.parametrize("lane", ["Bad", "a..b", "a.lock", "a.", "", "a" * 64, "a/b", None, "writer\n"])
def test_invalid_lane_writes_nothing(tmp_path, monkeypatch, lane):
    if not storage_confined.descriptor_supported():
        pytest.skip("requires descriptor-relative no-follow storage")
    opened = _opens(monkeypatch)
    home = tmp_path / "zzmarker-missing"
    result = binding.bind(str(home), str(tmp_path), lane, os.getpid())
    assert result == _refusal("invalid_lane")
    assert opened == []
    assert not home.exists()
    assert lane is None or not lane or str(lane) not in result["reason"]


@pytest.mark.parametrize("which,kind", [
    ("user", "relative"), ("user", "empty"), ("user", "nul"), ("user", "not-absolute"),
    ("workspace", "relative"), ("workspace", "empty"), ("workspace", "nul"), ("workspace", "not-absolute"),
])
def test_bad_roots_write_nothing(tmp_path, monkeypatch, which, kind):
    home = make_home(tmp_path)
    workspace = make_store(tmp_path)
    use_leases(monkeypatch, found(lease()))
    opened = _opens(monkeypatch)
    samples = {
        "relative": "relative",
        "empty": "",
        "nul": str(home) + "\x00",
        "not-absolute": "zz/nope",
    }
    user_root = samples[kind] if which == "user" else str(home)
    workspace_root = samples[kind] if which == "workspace" else str(workspace)
    if which == "workspace" and kind == "nul":
        workspace_root = str(workspace) + "\x00"
    result = binding.bind(user_root, workspace_root, "writer", os.getpid())
    assert result == _refusal("state_unavailable")
    assert opened == []
    assert not leaf(home).exists()
    assert "zzmarker" not in result["reason"]
    assert "\x00" not in result["reason"]


def test_missing_config_directory_is_not_created(tmp_path, monkeypatch):
    if not storage_confined.descriptor_supported():
        pytest.skip("requires descriptor-relative no-follow storage")
    home = tmp_path.resolve() / "zzmarker-home"
    home.mkdir()
    os.chmod(home, 0o700)
    workspace = make_store(tmp_path)
    use_leases(monkeypatch, found(lease()))
    result = call_bind(home, workspace)
    assert result == _refusal("state_unavailable")
    assert not (home / ".config").exists()


def test_ancestor_symlink_is_not_followed(tmp_path, monkeypatch):
    home = make_home(tmp_path)
    workspace = make_store(tmp_path)
    use_leases(monkeypatch, found(lease()))
    real = tmp_path / "real-config"
    real.mkdir()
    os.chmod(real, 0o700)
    aegis = home / ".config" / "aegis"
    aegis.rmdir()
    symlink_or_skip(real, aegis, target_is_directory=True)
    result = call_bind(home, workspace)
    assert result == _refusal("state_unavailable")
    assert not (real / binding.NAME).exists()


@pytest.mark.parametrize("symlink", [False, True])
def test_home_rename_after_fd_held_stays_on_the_descriptor(tmp_path, monkeypatch, symlink):
    home = make_home(tmp_path)
    workspace = make_store(tmp_path)
    config = home / ".config" / "aegis"
    parked = home / ".config" / "parked"
    decoy = tmp_path / "decoy"
    decoy.mkdir()
    os.chmod(decoy, 0o700)
    (decoy / binding.NAME).write_text("DECOY")

    def swap(workspace, lane):
        config.rename(parked)
        if symlink:
            symlink_or_skip(decoy, config, target_is_directory=True)
        else:
            config.mkdir()
            os.chmod(config, 0o700)
            (config / binding.NAME).write_text("SWAPPED")
        return lease()

    monkeypatch.setattr(binding, "_selected_lease", swap)
    result = call_bind(home, workspace)
    assert result == {"status": "ok"}
    written = (parked / binding.NAME).read_text(encoding="utf-8")
    assert "writer" in written
    assert (decoy / binding.NAME).read_text(encoding="utf-8") == "DECOY"
    if not symlink:
        assert (config / binding.NAME).read_text(encoding="utf-8") == "SWAPPED"


@pytest.mark.parametrize("mode", ["leaf", "directory", "owner"])
def test_unsafe_leaf_or_directory_keeps_bytes(tmp_path, monkeypatch, mode):
    home = make_home(tmp_path)
    workspace = make_store(tmp_path)
    use_leases(monkeypatch, found(lease()))
    path = leaf(home)
    if mode == "leaf":
        path.write_bytes(b"KEEP")
        os.chmod(path, 0o660)
    elif mode == "directory":
        os.chmod(home / ".config" / "aegis", 0o770)
    else:
        monkeypatch.setattr(binding, "_current_uid", lambda: os.getuid() + 1)
        path.write_bytes(b"KEEP")
        os.chmod(path, 0o600)
    result = call_bind(home, workspace)
    assert result == _refusal("state_unavailable")
    assert "zzmarker" not in result["reason"]
    if mode == "directory":
        assert not path.exists()
    else:
        assert path.read_bytes() == b"KEEP"


def test_leaf_symlink_keeps_target_bytes(tmp_path, monkeypatch):
    home = make_home(tmp_path)
    workspace = make_store(tmp_path)
    use_leases(monkeypatch, found(lease()))
    target = tmp_path / "target-bytes"
    target.write_bytes(b"KEEP")
    symlink_or_skip(target, leaf(home))
    result = call_bind(home, workspace)
    assert result == _refusal("state_unavailable")
    assert target.read_bytes() == b"KEEP"


def test_claim_exclusion_borrows_parent_fd_until_the_lock_is_released(tmp_path, monkeypatch):
    workspace = make_store(tmp_path)
    common = workspace / "common"
    common.mkdir()
    moved = workspace / "moved"
    lock_name = "aegis-writer.lock"
    borrowed = []
    lock_dir_fds = []

    @contextmanager
    def confined_file(root, parts):
        with storage_confined.confined_file(root, parts) as handle:
            parent_fd = handle.parent_fd
            borrowed.append(parent_fd)
            common.rename(moved)
            common.mkdir()
            yield SimpleNamespace(parent_fd=parent_fd)
            assert handle.parent_fd == parent_fd
            assert os.path.samestat(os.fstat(parent_fd), moved.stat())

    def record_file_lock(path, timeout=5.0, *, dir_fd=None):
        lock_dir_fds.append(dir_fd)
        return storage.file_lock(path, timeout=timeout, dir_fd=dir_fd)

    monkeypatch.setattr(binding, "gitsafe", SimpleNamespace(common_dir=lambda _: common))
    monkeypatch.setattr(binding, "storage_confined", SimpleNamespace(confined_file=confined_file))
    monkeypatch.setattr(binding, "storage", SimpleNamespace(
        file_lock=record_file_lock, LockTimeoutError=storage.LockTimeoutError))
    with binding.claim_exclusion(workspace):
        assert (moved / lock_name).is_file()
        assert not (common / lock_name).exists()
        assert os.path.samestat(os.fstat(borrowed[0]), moved.stat())

    assert lock_dir_fds == [borrowed[0]]
    with pytest.raises(OSError) as closed:
        os.fstat(borrowed[0])
    assert closed.value.errno == errno.EBADF


def test_claim_exclusion_refuses_a_closed_handle_then_retries(tmp_path, monkeypatch):
    workspace = make_store(tmp_path)
    lock_name = "aegis-writer.lock"
    with storage_confined.confined_file(workspace, (lock_name,)) as closed:
        pass

    monkeypatch.setattr(binding, "gitsafe", SimpleNamespace(common_dir=lambda _: workspace))
    monkeypatch.setattr(binding, "storage_confined", SimpleNamespace(confined_file=lambda *_: nullcontext(closed)))
    with pytest.raises(binding.BindingLockRefused, match="^writer lease is unavailable$") as refused:
        with binding.claim_exclusion(workspace):
            pytest.fail("claim lock accepted a closed handle")
    assert refused.value.code == "lease_unavailable"
    assert not (workspace / lock_name).exists()

    monkeypatch.setattr(binding, "storage_confined", storage_confined)
    with binding.claim_exclusion(workspace):
        assert (workspace / lock_name).is_file()


def test_second_bind_while_flock_held_then_retry_publishes(tmp_path, monkeypatch):
    home = make_home(tmp_path)
    workspace = make_store(tmp_path)
    started, release = threading.Event(), threading.Event()

    def blocked(workspace, lane):
        started.set()
        assert release.wait(5)
        return lease(lane)

    monkeypatch.setattr(binding, "_selected_lease", blocked)
    holder = {}

    def first():
        holder["result"] = call_bind(home, workspace, "writer")

    thread = threading.Thread(target=first)
    thread.start()
    assert started.wait(5)
    locked = call_bind(home, workspace, "other")
    assert locked == _refusal("state_locked")
    release.set()
    thread.join(5)
    assert not thread.is_alive()
    assert holder["result"] == {"status": "ok"}
    retried = call_bind(home, workspace, "other")
    assert retried == {"status": "ok"}
    saved = json.loads(leaf(home).read_text(encoding="utf-8"))
    assert set(saved["bindings"]) == {"other", "writer"}


def test_two_lanes_keep_both_records(tmp_path, monkeypatch):
    home = make_home(tmp_path)
    workspace = make_store(tmp_path)
    monkeypatch.setattr(binding, "_selected_lease", lambda workspace, lane: lease(lane))
    results = []

    pause = threading.Event()

    def run(lane):
        # Nonblocking flock refuses the overlapping attempt. Wait for the holder
        # to publish, then retry, so both records exist after serialization.
        for _ in range(50):
            result = call_bind(home, workspace, lane)
            if result.get("code") != "state_locked":
                results.append(result)
                return
            pause.wait(0.05)
        results.append(result)

    threads = [threading.Thread(target=run, args=(lane,)) for lane in ("writer", "other")]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(10)
        assert not thread.is_alive()
    assert results == [{"status": "ok"}, {"status": "ok"}]
    saved = json.loads(leaf(home).read_text(encoding="utf-8"))
    assert set(saved["bindings"]) == {"other", "writer"}


@pytest.mark.parametrize("kind", ["malformed", "duplicate", "version", "extra", "list"])
def test_malformed_binding_keeps_bytes(tmp_path, monkeypatch, kind):
    home = make_home(tmp_path)
    workspace = make_store(tmp_path)
    use_leases(monkeypatch, found(lease()))
    samples = {
        "malformed": b"{TOKEN=secret",
        "duplicate": b'{"bindings":{},"version":1,"version":1}\n',
        "version": b'{"bindings":{},"version":2}\n',
        "extra": b'{"bindings":{},"extra":"TOKEN=secret","version":1}\n',
        "list": b"[]\n",
    }
    path = leaf(home)
    path.write_bytes(samples[kind])
    os.chmod(path, 0o600)
    result = call_bind(home, workspace)
    assert result == _refusal("state_unavailable")
    assert path.read_bytes() == samples[kind]
    assert "TOKEN" not in repr(result)
    assert "secret" not in repr(result)


def test_oversize_binding_is_refused_before_parse(tmp_path, monkeypatch):
    home = make_home(tmp_path)
    workspace = make_store(tmp_path)
    use_leases(monkeypatch, found(lease()))
    path = leaf(home)
    original = b"y" * (binding.MAX_BYTES + 1)
    path.write_bytes(original)
    os.chmod(path, 0o600)

    def parsed(text):
        raise AssertionError("parsed")

    monkeypatch.setattr(binding, "_json_loads", parsed)
    monkeypatch.setattr(binding, "_preflight", parsed)
    result = call_bind(home, workspace)
    assert result == _refusal("state_unavailable")
    assert path.read_bytes() == original


def test_reader_refuses_oversize_bytes_before_parse(monkeypatch):
    if not storage_confined.descriptor_supported():
        pytest.skip("requires descriptor-relative no-follow storage")

    def parsed(text):
        raise AssertionError("parsed")

    monkeypatch.setattr(binding, "_json_loads", parsed)
    monkeypatch.setattr(binding, "_preflight", parsed)
    monkeypatch.setattr(binding, "read_owned_leaf", lambda *args, **kwargs: b"z" * (binding.MAX_BYTES + 1))
    with pytest.raises(binding._Refusal) as caught:
        binding._decode(binding.read_owned_leaf())
    assert caught.value.code == "state_unavailable"


def test_worst_case_document_decodes():
    if not storage_confined.descriptor_supported():
        pytest.skip("requires descriptor-relative no-follow storage")
    records = binding._decode(worst_document())
    assert len(records) == 256


@pytest.mark.parametrize("kind", ["error", "unreadable", "missing"])
def test_lease_failures_write_nothing(tmp_path, monkeypatch, kind):
    home = make_home(tmp_path)
    workspace = make_store(tmp_path)

    def read(workspace, lane):
        if kind == "error":
            raise RuntimeError("TOKEN=secret")
        raise binding._Refusal("lease_unavailable")

    monkeypatch.setattr(binding, "_selected_lease", read)
    result = call_bind(home, workspace)
    assert result == _refusal("lease_unavailable")
    assert not leaf(home).exists()
    assert "TOKEN" not in repr(result)
    assert "secret" not in repr(result)
    assert "zzmarker" not in result["reason"]


@pytest.mark.parametrize("symlink", [False, True])
def test_workspace_identity_change_writes_nothing(tmp_path, monkeypatch, symlink):
    home = make_home(tmp_path)
    workspace = tmp_path.resolve() / "workspace"
    workspace.mkdir()
    os.chmod(workspace, 0o700)
    if not storage_confined.descriptor_supported():
        pytest.skip("requires descriptor-relative no-follow storage")
    parked = tmp_path / "parked"
    other = tmp_path / "other"
    other.mkdir()

    def swap(root, lane):
        workspace.rename(parked)
        if symlink:
            symlink_or_skip(other, workspace, target_is_directory=True)
        else:
            workspace.mkdir()
            os.chmod(workspace, 0o700)
        return lease()

    monkeypatch.setattr(binding, "_selected_lease", swap)
    result = call_bind(home, workspace)
    assert result == _refusal("lease_unavailable")
    assert not leaf(home).exists()


def test_unreadable_scope_writes_nothing(tmp_path, monkeypatch):
    home = make_home(tmp_path)
    workspace = make_store(tmp_path)
    use_leases(monkeypatch, found(lease()))

    def unavailable():
        raise binding._Refusal("identity_unavailable")

    monkeypatch.setattr(binding, "_scope", unavailable)
    result = call_bind(home, workspace)
    assert result == _refusal("identity_unavailable")
    assert not leaf(home).exists()


@pytest.mark.parametrize("field,value", [
    ("boot_id", "abcdefab-1234-1234-1234-123456789abc"),
    ("pid_namespace", "pid:[54321]"),
])
@pytest.mark.parametrize("existing", [False, True])
def test_scope_change_during_lease_refuses_then_retries(tmp_path, monkeypatch, field, value, existing):
    home = make_home(tmp_path)
    workspace = make_store(tmp_path)
    use_leases(monkeypatch, found(lease()))
    if existing:
        assert call_bind(home, workspace) == {"status": "ok"}
    frozen = leaf(home).read_bytes() if existing else None
    original = binding._scope()
    scope = dict(original)
    monkeypatch.setattr(binding, "_scope", lambda: dict(scope))

    def changed(workspace, lane):
        scope[field] = value
        return lease(lane)

    monkeypatch.setattr(binding, "_selected_lease", changed)
    for _ in range(2):
        scope.update(original)
        assert call_bind(home, workspace) == _refusal("identity_unavailable")
        assert (leaf(home).read_bytes() if existing else None) == frozen
        assert leaf(home).exists() == existing
    use_leases(monkeypatch, found(lease()))
    assert call_bind(home, workspace) == {"status": "ok"}


def test_scope_change_under_concurrent_bind_never_publishes(tmp_path, monkeypatch):
    home = make_home(tmp_path)
    workspace = make_store(tmp_path)
    scope = binding._scope()
    started, release = threading.Event(), threading.Event()
    monkeypatch.setattr(binding, "_scope", lambda: dict(scope))

    def changed(workspace, lane):
        started.set()
        assert release.wait(5)
        scope["pid_namespace"] = "pid:[54321]"
        return lease(lane)

    monkeypatch.setattr(binding, "_selected_lease", changed)
    result = {}
    thread = threading.Thread(target=lambda: result.update(call_bind(home, workspace)))
    thread.start()
    try:
        assert started.wait(5)
        assert call_bind(home, workspace) == _refusal("state_locked")
    finally:
        release.set()
        thread.join(5)
    assert not thread.is_alive()
    assert result == _refusal("identity_unavailable")
    assert not leaf(home).exists()
    use_leases(monkeypatch, found(lease()))
    assert call_bind(home, workspace) == {"status": "ok"}


def test_absent_pid_writes_nothing(tmp_path, monkeypatch):
    home = make_home(tmp_path)
    workspace = make_store(tmp_path)
    use_leases(monkeypatch, found(lease()))
    result = call_bind(home, workspace, pid=absent_pid())
    assert result == _refusal("identity_unavailable")
    assert not leaf(home).exists()


def test_zombie_pid_writes_nothing(tmp_path, monkeypatch):
    home = make_home(tmp_path)
    workspace = make_store(tmp_path)
    use_leases(monkeypatch, found(lease()))
    if not hasattr(os, "fork") or not hasattr(os, "waitid") or not hasattr(os, "WNOWAIT"):
        pytest.skip("fork unavailable")
    pid = os.fork()
    if pid == 0:
        os._exit(0)
    try:
        os.waitid(os.P_PID, pid, os.WEXITED | os.WNOWAIT)
        result = call_bind(home, workspace, pid=pid)
    finally:
        os.waitpid(pid, 0)
    assert result == _refusal("identity_unavailable")
    assert not leaf(home).exists()


def test_other_live_pid_is_ambiguous_and_keeps_bytes(tmp_path, monkeypatch):
    home = make_home(tmp_path)
    workspace = make_store(tmp_path)
    use_leases(monkeypatch, found(lease()))
    program = shutil.which("sleep")
    if program is None:
        pytest.skip("sleep unavailable")
    process = subprocess.Popen([program, "30"])
    try:
        assert call_bind(home, workspace, pid=process.pid) == {"status": "ok"}
        before = leaf(home).read_bytes()
        result = call_bind(home, workspace, pid=os.getpid())
        assert result == _refusal("identity_ambiguous")
        assert leaf(home).read_bytes() == before
        assert str(process.pid) not in result["reason"]
    finally:
        process.kill()
        process.wait(timeout=5)


def test_same_live_pid_stores_advanced_gen(tmp_path, monkeypatch):
    home = make_home(tmp_path)
    workspace = make_store(tmp_path)
    state = {"gen": 1}
    monkeypatch.setattr(binding, "_selected_lease", lambda workspace, lane: lease(gen=state["gen"]))
    assert call_bind(home, workspace) == {"status": "ok"}
    state["gen"] = 2
    assert call_bind(home, workspace) == {"status": "ok"}
    saved = json.loads(leaf(home).read_text(encoding="utf-8"))
    assert saved["bindings"]["writer"]["gen"] == 2
    assert saved["bindings"]["writer"]["claim_id"] == "a" * 16
    assert saved["bindings"]["writer"]["pid"] == os.getpid()


def test_identical_record_keeps_equivalent_bytes(tmp_path, monkeypatch):
    home = make_home(tmp_path)
    workspace = make_store(tmp_path)
    use_leases(monkeypatch, found(lease()))
    assert call_bind(home, workspace) == {"status": "ok"}
    before = leaf(home).read_bytes()
    assert call_bind(home, workspace) == {"status": "ok"}
    assert leaf(home).read_bytes() == before
    assert stat.S_IMODE(leaf(home).stat().st_mode) == 0o600
    assert before.startswith(b'{"bindings":')
    assert b" " not in before


def test_publish_failure_keeps_bytes_and_closes_fds(tmp_path, monkeypatch):
    home = make_home(tmp_path)
    workspace = make_store(tmp_path)
    state = {"gen": 1}
    monkeypatch.setattr(binding, "_selected_lease", lambda workspace, lane: lease(gen=state["gen"]))
    before_fds = set(os.listdir("/proc/self/fd"))
    assert call_bind(home, workspace) == {"status": "ok"}
    before = leaf(home).read_bytes()
    held = []

    def boom(directory, data):
        held.append(directory)
        raise OSError("TOKEN=secret")

    monkeypatch.setattr(binding, "_publish_leaf", boom)
    state["gen"] = 2
    result = call_bind(home, workspace)
    assert result == _refusal("state_unavailable")
    assert leaf(home).read_bytes() == before
    assert "TOKEN" not in repr(result)
    assert held
    with pytest.raises(OSError):
        os.fstat(held[0])
    assert set(os.listdir("/proc/self/fd")) == before_fds


def test_successful_bind_closes_fds_and_records_the_lease_triple(tmp_path, monkeypatch):
    home = make_home(tmp_path)
    workspace = make_store(tmp_path)
    use_leases(monkeypatch, found(lease(claim="abcdef0123456789", gen=4)))
    before = set(os.listdir("/proc/self/fd"))
    assert "claim_id" not in binding.bind.__code__.co_varnames
    assert "gen" not in binding.bind.__code__.co_varnames
    assert call_bind(home, workspace) == {"status": "ok"}
    assert set(os.listdir("/proc/self/fd")) == before
    row = json.loads(leaf(home).read_text(encoding="utf-8"))["bindings"]["writer"]
    scope = binding._scope()
    identity = binding.process_identity(os.getpid())
    assert row["claim_id"] == "abcdef0123456789"
    assert row["gen"] == 4
    assert row["pid"] == identity["pid"]
    assert row["start_ticks"] == identity["start_ticks"]
    assert row["boot_id"] == scope["boot_id"]
    assert row["pid_namespace"] == scope["pid_namespace"]


def _fds():
    if os.name != "posix" or not os.path.isdir("/proc/self/fd"):
        return None
    return set(os.listdir("/proc/self/fd"))


def _require_linux_identity():
    if not kernel_identity.descriptor_supported():
        pytest.skip("requires Linux identity support")


def _require_storage_descriptors():
    if not storage_confined.descriptor_supported():
        pytest.skip("requires descriptor-relative no-follow storage")


def test_each_judge_publishes_its_own_observation(monkeypatch):
    """A constant observe result is still a new publication. The verdict stays bare."""
    constant = {"binding": "no_binding_config", "verdict": {
        "state": "unknown", "reason": "bindings_unavailable", "leases": {}}}
    monkeypatch.setattr(binding, "observe", lambda *args: constant)
    token = binding.observation_token()
    assert binding.observation_since(token) is None
    judged = binding.judge("unused", "unused", {})
    assert judged == constant["verdict"] and "binding" not in judged
    assert binding.observation_since(token) is constant
    again = binding.observation_token()
    assert binding.judge("unused", "unused", {}) == judged
    assert binding.observation_since(again) is constant
    assert binding.observation_since(token) is constant


def test_observe_unsupported_platform_does_not_open(monkeypatch, tmp_path):
    """Unsupported probes are storage-unsafe and never touch a home."""
    opened = _opens(monkeypatch)
    probes = {"storage": 0}

    def storage_probe():
        probes["storage"] += 1
        return False

    def refused(*args, **kwargs):
        opened.append(args)
        raise AssertionError("unsupported probe must not open")

    monkeypatch.setattr(binding.storage_confined, "descriptor_supported", storage_probe)
    monkeypatch.setattr(binding.storage_confined, "open_directory", refused)
    home = tmp_path / "zzmarker-home"
    summary = {}
    observed = binding.observe(str(home), found(lease()), summary)
    judged = binding.judge(str(home), found(lease()), summary)
    assert observed["binding"] == "storage_unsafe"
    assert observed["verdict"]["reason"] == "bindings_unavailable"
    assert "lanes" not in observed["verdict"]
    assert judged == observed["verdict"]
    assert "binding" not in judged
    assert probes["storage"] >= 1
    assert opened == []
    assert not home.exists()


def test_invalid_observation_inputs_do_not_open(monkeypatch, tmp_path):
    opened = _opens(monkeypatch)
    home = tmp_path / "zzmarker-home"
    observed = binding.observe(str(home), "not-a-lease-set", [])
    assert observed["binding"] == "storage_unsafe"
    assert observed["verdict"] == {
        "state": "unknown", "reason": "bindings_unavailable", "leases": {}}
    assert binding.judge(str(home), "not-a-lease-set", []) == observed["verdict"]
    assert opened == []
    assert not home.exists()


def test_missing_config_directory_is_absence_not_storage_failure(tmp_path):
    """Absence is a binding fact. Retry does not create the directory."""
    _require_linux_identity()
    home = tmp_path.resolve() / "zzmarker-home"
    home.mkdir()
    os.chmod(home, 0o700)
    chosen = found(lease())
    before = _fds()
    observed = binding.observe(str(home), chosen, {})
    assert observed["binding"] == "no_binding_config"
    assert observed["verdict"]["reason"] == "bindings_unavailable"
    assert "lanes" not in observed["verdict"]
    assert "zzmarker" not in repr(observed)
    judged = binding.judge(str(home), chosen, {})
    assert judged == {"state": "unknown", "reason": "bindings_unavailable", "leases": {}}
    assert judged == binding.observe(str(home), chosen, {})["verdict"]
    again = binding.observe(str(home), chosen, {})
    assert again["binding"] == "no_binding_config"
    assert not (home / ".config").exists()
    if before is not None:
        assert _fds() == before


def test_missing_binding_file_is_ready_and_projects_judge(tmp_path):
    _require_linux_identity()
    home = make_home(tmp_path)
    chosen = found(lease())
    observed = binding.observe(str(home), chosen, {})
    assert observed["binding"] == "ready"
    assert observed["verdict"]["reason"] == "no_bound_liveness_source"
    assert binding.judge(str(home), chosen, {}) == observed["verdict"]
    assert "binding" not in binding.judge(str(home), chosen, {})


def test_config_symlink_is_storage_unsafe_not_absence(tmp_path):
    _require_linux_identity()
    home = make_home(tmp_path)
    config = home / ".config" / "aegis"
    config.rmdir()
    outside = tmp_path / "outside-config"
    outside.mkdir()
    os.chmod(outside, 0o700)
    symlink_or_skip(outside, config, target_is_directory=True)
    before = _fds()
    observed = binding.observe(str(home), found(lease()), {})
    assert observed["binding"] == "storage_unsafe"
    assert observed["verdict"]["reason"] == "bindings_unavailable"
    assert binding.judge(str(home), found(lease()), {})["reason"] == "bindings_unavailable"
    assert not (outside / binding.NAME).exists()
    assert "outside-config" not in repr(observed)
    if before is not None:
        assert _fds() == before


def test_malformed_binding_stays_unsafe_on_retry(tmp_path):
    _require_linux_identity()
    home = make_home(tmp_path)
    path = leaf(home)
    path.write_bytes(b"{")
    os.chmod(path, 0o600)
    before_bytes = path.read_bytes()
    before = _fds()
    observed = binding.observe(str(home), found(lease()), {})
    assert observed["binding"] == "storage_unsafe"
    assert observed["verdict"]["reason"] == "bindings_unavailable"
    assert path.read_bytes() == before_bytes
    assert binding.observe(str(home), found(lease()), {})["binding"] == "storage_unsafe"
    assert path.read_bytes() == before_bytes
    if before is not None:
        assert _fds() == before


def test_concurrent_observations_do_not_create_config_or_leak(tmp_path):
    _require_linux_identity()
    home = tmp_path.resolve() / "zzmarker-home"
    home.mkdir()
    os.chmod(home, 0o700)
    before = _fds()
    barrier = threading.Barrier(4)
    results = []
    errors = []

    def worker():
        try:
            barrier.wait(timeout=5)
            results.append(binding.observe(str(home), found(lease()), {})["binding"])
        except Exception as error:
            errors.append(error)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    assert errors == []
    assert results == ["no_binding_config"] * 4
    assert not (home / ".config").exists()
    if before is not None:
        assert _fds() == before


def test_missing_passwd_home_is_storage_not_absence(tmp_path):
    _require_storage_descriptors()
    missing = tmp_path.resolve() / "no-such-zzmarker-home"
    before = _fds()
    observed = binding.observe(str(missing), found(lease()), {})
    assert observed["binding"] == "storage_unsafe"
    assert observed["verdict"]["reason"] == "bindings_unavailable"
    assert "zzmarker" not in repr(observed)
    assert not missing.exists()
    if before is not None:
        assert _fds() == before


def _foreign_uid():
    return 0 if os.getuid() != 0 else 1


class _HeldDirectory:
    """Test double for DirectoryAnchor. Closes its own dup and nothing else."""

    def __init__(self, source, observations):
        self.fd = os.dup(source)
        self.observations = observations

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        return False


def _patch_descriptor_facts(monkeypatch, tmp_path, observations, child):
    """Replace the home walk and the two fixed descents. Does not patch os.open or os.close."""
    _require_storage_descriptors()
    source_dir = tmp_path / "anchor-source"
    source_dir.mkdir()
    source = os.open(source_dir, os.O_RDONLY | os.O_DIRECTORY)
    opened = []

    def open_directory(_opener, root, **_kwargs):
        opened.append(os.fspath(root))
        return _HeldDirectory(source, observations)

    monkeypatch.setattr(binding, "open_directory", open_directory)
    monkeypatch.setattr(binding, "_open_config_child", child)
    monkeypatch.setattr(binding.storage_confined, "descriptor_supported", lambda: True)
    return opened, source


@pytest.mark.parametrize("missing, ownership, mode, spelling, expected", [
    (".config", "owner", 0o755, "/home/writer", "no_binding_config"),
    ("aegis", "owner", 0o755, "/home/writer", "no_binding_config"),
    (".config", "foreign", 0o755, "/home/writer", "storage_unsafe"),
    ("aegis", "foreign", 0o755, "/home/writer", "storage_unsafe"),
    (".config", "root", 0o755, "/", "no_binding_config"),
    (".config", "root", 0o755, "/home/writer", "storage_unsafe"),
    (".config", "root", 0o755, "//", "storage_unsafe"),
    (".config", "foreign", 0o755, "/", "storage_unsafe"),
    ("aegis", "root", 0o755, "/", "storage_unsafe"),
    ("aegis", "owner", 0o755, "/", "no_binding_config"),
    (".config", "root", 0o775, "/", "storage_unsafe"),
    ("aegis", "owner", 0o757, "/", "storage_unsafe"),
])
def test_missing_child_requires_trusted_descriptor_facts(tmp_path, monkeypatch, missing, ownership,
                                                         mode, spelling, expected):
    owner = 1001
    uid = {"owner": owner, "root": 0, "foreign": 1002}[ownership]
    monkeypatch.setattr(binding, "_current_uid", lambda: owner)
    home_uid = uid if missing == ".config" else (0 if spelling == "/" else owner)
    home_mode = mode if missing == ".config" else 0o755
    home = (1, 2, home_uid, stat.S_IFDIR | home_mode)
    children = []

    def open_child(parent, name):
        children.append(name)
        if name == missing:
            raise FileNotFoundError(name)
        return os.dup(parent), (1, 3, uid, stat.S_IFDIR | mode)

    opened, source = _patch_descriptor_facts(monkeypatch, tmp_path, (home,), open_child)
    try:
        before = _fds()
        for value in (spelling, Path(spelling)):
            observed = binding.observe(value, found(lease()), {})
            assert observed["binding"] == expected, observed
            assert observed["verdict"]["reason"] == "bindings_unavailable"
        assert opened == [spelling, spelling]
        names = [".config"] if missing == ".config" else [".config", "aegis"]
        assert children == names * 2
        if before is not None:
            assert _fds() == before
    finally:
        os.close(source)


def test_private_leaf_remains_authoritative_under_foreign_writable_home(tmp_path, monkeypatch):
    """A safe system-root home can establish absence when a child is missing.

    A present owner-private aegis directory stays authoritative. Group-writable
    ancestry with a missing child stays storage.
    """
    if os.name != "posix" or not hasattr(os, "getuid"):
        pytest.skip("requires a passwd uid")
    root_owned = (1, 2, 0, stat.S_IFDIR | 0o755)
    writable = (1, 2, _foreign_uid(), stat.S_IFDIR | 0o777)
    reads = []

    def missing(_parent, _name):
        raise FileNotFoundError(_name)

    def present(_parent, name):
        source = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
        if name == "aegis":
            info = SimpleNamespace(st_uid=os.getuid(), st_mode=stat.S_IFDIR | 0o700, st_dev=1, st_ino=4)
        else:
            info = SimpleNamespace(st_uid=_foreign_uid(), st_mode=stat.S_IFDIR | 0o755, st_dev=1, st_ino=3)
        return source, info

    def read_map(directory):
        reads.append(directory)
        return {}

    opened, anchor = _patch_descriptor_facts(monkeypatch, tmp_path, (root_owned,), missing)
    try:
        absent = binding.observe("/", found(lease()), {})
        assert absent["binding"] == "no_binding_config"
        assert opened == ["/"]
        opened.clear()
        monkeypatch.setattr(binding, "open_directory", lambda _opener, root, **_kwargs: (
            opened.append(os.fspath(root)) or _HeldDirectory(
                anchor, ((1, 2, _foreign_uid(), stat.S_IFDIR | 0o777),))))
        monkeypatch.setattr(binding, "_open_config_child", present)
        monkeypatch.setattr(binding, "_read_map", read_map)
        present_leaf = binding.observe("/", found(lease()), {})
        assert present_leaf["binding"] != "no_binding_config"
        assert reads, "a present private leaf is read"
        if kernel_identity.descriptor_supported():
            assert present_leaf["binding"] == "ready"
        else:
            assert present_leaf["binding"] == "storage_unsafe"
        opened.clear()
        monkeypatch.setattr(binding, "_open_config_child", missing)
        _patch_opened = opened
        monkeypatch.setattr(binding, "open_directory", lambda _opener, root, **_kwargs: (
            _patch_opened.append(os.fspath(root)) or _HeldDirectory(anchor, (writable,))))
        unsafe = binding.observe("/", found(lease()), {})
        assert unsafe["binding"] == "storage_unsafe"
    finally:
        os.close(anchor)


def test_root_passwd_home_uses_descriptor_facts(root_binding_case):
    home, allows_absence, assert_walk_closed = root_binding_case
    observed = binding.observe(home, found(lease()), {})
    assert observed["binding"] == ("no_binding_config" if allows_absence else "storage_unsafe")
    assert observed["verdict"]["reason"] == "bindings_unavailable"
    assert "lanes" not in observed["verdict"]
    assert_walk_closed()


def test_missing_aegis_under_group_writable_config_is_storage(tmp_path):
    _require_storage_descriptors()
    home = tmp_path.resolve() / "zzmarker-home"
    config = home / ".config"
    config.mkdir(parents=True)
    os.chmod(home, 0o700)
    os.chmod(config, 0o770)
    before = _fds()
    observed = binding.observe(str(home), found(lease()), {})
    assert observed["binding"] == "storage_unsafe"
    assert not (config / "aegis").exists()
    assert "zzmarker" not in repr(observed)
    if before is not None:
        assert _fds() == before


def test_descriptor_proven_absence_without_kernel_identity(tmp_path, monkeypatch):
    _require_storage_descriptors()
    monkeypatch.setattr(binding, "descriptor_supported", lambda: False)
    home = tmp_path.resolve() / "zzmarker-home"
    home.mkdir()
    os.chmod(home, 0o700)
    before = _fds()
    observed = binding.observe(str(home), found(lease()), {})
    assert observed["binding"] == "no_binding_config"
    assert binding.judge(str(home), found(lease()), {})["reason"] == "bindings_unavailable"
    assert not (home / ".config").exists()
    if before is not None:
        assert _fds() == before


def test_present_config_without_kernel_identity_stays_unsafe(tmp_path, monkeypatch):
    _require_storage_descriptors()
    monkeypatch.setattr(binding, "descriptor_supported", lambda: False)
    home = make_home(tmp_path)
    observed = binding.observe(str(home), found(lease()), {})
    assert observed["binding"] == "storage_unsafe"
    assert observed["verdict"]["reason"] == "bindings_unavailable"


def test_absence_ignores_binding_spelling_limits(tmp_path):
    _require_storage_descriptors()
    home = tmp_path.resolve() / "zz\nmarker"
    home.mkdir()
    os.chmod(home, 0o700)
    with pytest.raises(binding._Refusal):
        binding._root(str(home))
    before = _fds()
    observed = binding.observe(str(home), found(lease()), {})
    assert observed["binding"] == "no_binding_config"
    assert not (home / ".config").exists()
    assert "\n" not in repr(observed)
    if before is not None:
        assert _fds() == before


def test_absence_under_a_deep_home_spelling(tmp_path):
    _require_storage_descriptors()
    home = tmp_path.resolve().joinpath(*(["d"] * 130))
    if len(str(home)) > 32768:
        pytest.skip("home spelling exceeds confined storage")
    home.mkdir(parents=True)
    os.chmod(home, 0o700)
    spelling = str(home)
    assert spelling.count("/") + spelling.count("\\") > 128
    with pytest.raises(binding._Refusal):
        binding._root(spelling)
    observed = binding.observe(spelling, found(lease()), {})
    assert observed["binding"] == "no_binding_config"
    assert not (home / ".config").exists()


@pytest.mark.parametrize("length", [32754, 32755, 32768])
def test_absence_uses_the_home_budget_not_the_config_suffix(tmp_path, monkeypatch, length):
    """The home keeps the full 32768-character root budget. .config and aegis are descents."""
    spelling = "/" + ("h" * (length - 1))
    assert len(spelling) == length
    home_fact = (1, 2, os.getuid() if hasattr(os, "getuid") else 0, stat.S_IFDIR | 0o700)

    def missing(_parent, name):
        raise FileNotFoundError(name)

    opened, source = _patch_descriptor_facts(monkeypatch, tmp_path, (home_fact,), missing)
    before = _fds()
    try:
        observed = binding.observe(spelling, found(lease()), {})
        assert observed["binding"] == "no_binding_config", observed
        assert opened == [spelling]
        assert "/.config/aegis" not in opened[0]
        same = binding.observe(Path(spelling), found(lease()), {})
        assert same["binding"] == "no_binding_config"
        assert opened[-1] == spelling
        if before is not None:
            assert _fds() == before
    finally:
        os.close(source)


@pytest.mark.parametrize("spelling", ["/" + "h" * 32768, "/" * 32769], ids=["component", "separators"])
def test_overlong_home_is_storage_before_the_walk(monkeypatch, spelling):
    assert len(spelling) == 32769
    opened = []

    def open_directory(*_args, **_kwargs):
        opened.append(True)
        raise AssertionError("overlong home must be refused before open_directory")

    monkeypatch.setattr(binding, "open_directory", open_directory)
    monkeypatch.setattr(binding.storage_confined, "descriptor_supported", lambda: True)
    observed = binding.observe(spelling, found(lease()), {})
    assert observed["binding"] == "storage_unsafe"
    assert opened == []
    assert "h" * 40 not in repr(observed)


@pytest.mark.parametrize("spelling", ["/" + "h" * 32754, "/" * 129], ids=["length", "separators"])
def test_present_leaf_past_the_binding_spelling_limit_is_storage(tmp_path, monkeypatch, spelling):
    """Apply the original spelling limits when a private directory is present."""
    home_fact = (1, 2, os.getuid() if hasattr(os, "getuid") else 0, stat.S_IFDIR | 0o700)
    source_box = []

    def present(_parent, name):
        fd = os.dup(source_box[0])
        info = SimpleNamespace(st_uid=os.getuid() if hasattr(os, "getuid") else 0,
                               st_mode=stat.S_IFDIR | 0o700, st_dev=1, st_ino=4)
        return fd, info

    opened, source = _patch_descriptor_facts(monkeypatch, tmp_path, (home_fact,), present)
    source_box.append(source)
    reads = []
    monkeypatch.setattr(binding, "_read_map", lambda directory: reads.append(directory) or {})
    before = _fds()
    try:
        observed = binding.observe(spelling, found(lease()), {})
        assert observed["binding"] == "storage_unsafe"
        assert reads == []
        assert opened == [str(Path(spelling))]
        if spelling.endswith("/"):
            binding.observe(Path(spelling), found(lease()), {})
            assert len(reads) == 1
        if before is not None:
            assert _fds() == before
    finally:
        os.close(source)


def test_path_and_str_homes_observe_the_same_binding(tmp_path):
    home = make_home(tmp_path)
    chosen = found(lease())
    as_path = binding.observe(home, chosen, {})
    as_text = binding.observe(str(home), chosen, {})
    assert as_path["binding"] == as_text["binding"]
    assert binding.judge(home, chosen, {}) == binding.judge(str(home), chosen, {})
    if kernel_identity.descriptor_supported():
        assert as_path["binding"] == "ready"


def test_group_writable_home_is_storage_when_config_is_missing(tmp_path):
    _require_storage_descriptors()
    home = tmp_path.resolve() / "zzmarker-home"
    home.mkdir()
    os.chmod(home, 0o775)
    before = _fds()
    observed = binding.observe(str(home), found(lease()), {})
    assert observed["binding"] == "storage_unsafe"
    assert not (home / ".config").exists()
    if before is not None:
        assert _fds() == before


def test_group_writable_home_keeps_a_private_binding_directory(tmp_path):
    _require_linux_identity()
    home = make_home(tmp_path)
    os.chmod(home, 0o775)
    os.chmod(home / ".config", 0o700)
    os.chmod(home / ".config" / "aegis", 0o700)
    before = _fds()
    observed = binding.observe(home, found(lease()), {})
    assert observed["binding"] == "ready", observed
    assert binding.observe(str(home), found(lease()), {})["binding"] == "ready"
    if before is not None:
        assert _fds() == before


def test_config_child_closes_when_fstat_fails(tmp_path, monkeypatch):
    """A child descriptor is closed when the post-open stat fails."""
    _require_storage_descriptors()
    home = tmp_path.resolve() / "zzmarker-home"
    config = home / ".config"
    config.mkdir(parents=True)
    os.chmod(home, 0o700)
    os.chmod(config, 0o700)

    opened = []

    def fail_fstat(fd):
        opened.append(fd)
        raise OSError(1, "injected")

    parent = os.open(home, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    before = _fds()
    try:
        monkeypatch.setattr(binding, "_fstat", fail_fstat)
        with pytest.raises(binding._Refusal) as caught:
            binding._open_config_child(parent, ".config")
        assert caught.value.code == "state_unavailable"
        assert "injected" not in str(caught.value)
        assert len(opened) == 1
        with pytest.raises(OSError) as closed:
            os.fstat(opened[0])
        assert closed.value.errno == errno.EBADF
        if before is not None:
            assert _fds() == before
    finally:
        os.close(parent)


def test_unsupported_platform_does_not_descend_config_children(monkeypatch, tmp_path):
    """The storage probe is the gate. A false probe never opens the home or a child."""
    calls = []

    def child(*_args, **_kwargs):
        calls.append("child")
        raise AssertionError("unsupported probe must not descend")

    def storage_probe():
        calls.append("probe")
        return False

    monkeypatch.setattr(binding.storage_confined, "descriptor_supported", storage_probe)
    monkeypatch.setattr(binding, "_open_config_child", child)
    monkeypatch.setattr(binding, "open_directory", lambda *_args, **_kwargs: calls.append("open"))
    observed = binding.observe(str(tmp_path / "zzmarker-home"), found(lease()), {})
    assert observed["binding"] == "storage_unsafe"
    assert calls == ["probe"]
    assert not (tmp_path / "zzmarker-home").exists()
