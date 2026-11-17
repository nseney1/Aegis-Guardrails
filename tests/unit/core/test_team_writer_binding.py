"""Owner-home writer bindings with shared capability-gated fixtures.

Lease fixtures use memory or disposable repositories. Nothing reads the product checkout's git
history. Descriptor, symlink, and mode cases skip when the platform cannot
support them. The unsupported path monkeypatches this module's
descriptor_supported and does not open a home.
"""
from __future__ import annotations

from contextlib import contextmanager
import json
import os
import shutil
import stat
import subprocess
import threading
from types import SimpleNamespace

import pytest

from aegis_core import storage_confined, team
from aegis_core import team_writer_binding as binding
from tests.conftest import symlink_or_skip
from tests.helpers_writer_binding import call_bind, lease, make_home, make_store


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
