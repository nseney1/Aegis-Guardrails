"""Explicit observations through product services and owned OS boundaries."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from copy import deepcopy
import json
import os
import subprocess
from types import SimpleNamespace

import pytest

from aegis_core import gitsafe, storage_confined, team, team_hosts, team_profile, team_queue
from aegis_core import team_supervisor_observe as module


def make_store(tmp_path):
    if not storage_confined.descriptor_supported():
        pytest.skip("requires descriptor-relative no-follow storage")
    root = tmp_path.resolve() / "workspace"
    (root / ".aegis").mkdir(parents=True)
    return root


def symlink_or_skip(link, target, directory=False):
    try:
        link.symlink_to(target, target_is_directory=directory)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")


def profile(source="subscription-window", pair=False):
    names = ("primary", "review") if pair else ("primary",)
    return team_profile.resolve(preset="pair" if pair else "solo", repo={
        "model_settings": {"capacity": {name: {"usage_source": source} for name in names}},
    })


def adapter(used=10, pair=False):
    names = ("primary", "review") if pair else ("primary",)
    return team_hosts.FakeUsageAdapter({name: {"window": {
        "used_pct": used, "resets_at": "2026-11-16T00:00:00Z",
    }, "tokens": 40, "runs": 2} for name in names})


@pytest.fixture
def services(monkeypatch):
    monkeypatch.setattr(gitsafe, "run_checked", lambda *args, **kwargs: SimpleNamespace(stdout=b""))
    monkeypatch.setattr(team, "read_leases", lambda root: team.LeaseSet())
    monkeypatch.setattr(team_queue, "audit", lambda root, **kwargs: {
        "status": "done", "refused": False, "exit_code": 0, "items": [], "findings": [],
    })


def run(root, resolved=None, reader=None, now=100):
    return module.observe(profile() if resolved is None else resolved, workspace_root=root,
                          now=now, usage_adapter=adapter() if reader is None else reader)


def observations(result):
    assert result["status"] == "ok"
    assert result["starts_nothing"] is True and result["writes_nothing"] is True
    assert set(result["observations"]) == {"writer_dead", "disk", "capacity", "usage", "audit"}
    return result["observations"]


def lease(ts=50, ttl=100):
    raw = json.dumps({"v": 1, "lane": "writer", "role": "implementer", "owner": "owner",
                      "claim_id": "a" * 16, "gen": 1, "branch": "lane/writer",
                      "paths": ["docs/**"], "ts": ts, "ttl_s": ttl}).encode()
    return team.parse_lease(raw, "writer", "a" * 40)


@pytest.mark.parametrize("case,expected", [
    ("live", {"state": "known", "live": 1, "expired": 0, "unreadable": 0}),
    ("expired", {"state": "known", "live": 0, "expired": 1, "unreadable": 0}),
    ("missing", {"state": "known", "live": 0, "expired": 0, "unreadable": 0}),
    ("unreadable", {"state": "unknown", "live": 0, "expired": 0, "unreadable": 1}),
])
def test_no_lease_state_proves_writer_dead(tmp_path, monkeypatch, services, case, expected):
    root = make_store(tmp_path)
    found = {"live": team.LeaseSet((lease(),)), "expired": team.LeaseSet((lease(ttl=50),)),
             "missing": team.LeaseSet(), "unreadable": team.LeaseSet((), (
                 team.Unreadable("writer", "refs/aegis/lanes/writer", "a" * 40, "TOKEN=secret"),))}[case]
    monkeypatch.setattr(team, "read_leases", lambda root: found)
    for _ in range(2):
        row = observations(run(root))["writer_dead"]
        assert row == {"state": "unknown", "reason": "no_bound_liveness_source", "leases": expected}


def test_lease_read_error_is_unknown_without_diagnostic(tmp_path, monkeypatch, services):
    root = make_store(tmp_path)
    def failed(root):
        raise PermissionError("TOKEN=secret\ntrace")
    monkeypatch.setattr(team, "read_leases", failed)
    for _ in range(2):
        result = run(root)
        assert observations(result)["writer_dead"]["leases"] == {
            "state": "unknown", "reason": "leases_unavailable"}
        assert "secret" not in repr(result)
        assert result["observations"]["audit"]["state"] == "clean"


@pytest.mark.parametrize("symlink", [False, True])
def test_root_swapped_during_service_does_not_publish_redirected_facts(
    tmp_path, monkeypatch, services, symlink,
):
    root = make_store(tmp_path)
    parked = root.with_name("parked")
    other = root.with_name("other")
    other.mkdir()
    def swapped(path):
        root.rename(parked)
        if symlink:
            symlink_or_skip(root, other, directory=True)
        else:
            root.mkdir()
        return team.LeaseSet((lease(),))
    monkeypatch.setattr(team, "read_leases", swapped)
    rows = observations(run(root))
    assert rows["writer_dead"]["leases"]["state"] == "unknown"
    assert rows["audit"]["state"] == "unknown"
    assert rows["capacity"]["state"] == "available"


def test_linked_workspace_never_reaches_repository_services(tmp_path, monkeypatch, services):
    root = make_store(tmp_path)
    link = root.with_name("link")
    symlink_or_skip(link, root, directory=True)
    def unexpected(root):
        pytest.fail("linked workspace reached lease reads")
    monkeypatch.setattr(team, "read_leases", unexpected)
    rows = observations(run(link))
    assert rows["writer_dead"]["leases"]["state"] == "unknown"
    assert rows["disk"]["state"] == rows["audit"]["state"] == "unknown"


@pytest.mark.parametrize("free,state", [(5000, "healthy"), (4096, "healthy"), (4095, "below_floor")])
def test_disk_floor_uses_held_descriptor(tmp_path, monkeypatch, services, free, state):
    root = make_store(tmp_path)
    if not hasattr(os, "statvfs"):
        pytest.skip("statvfs unavailable")
    seen = []
    def disk(fd):
        assert type(fd) is int and os.fstat(fd).st_ino == root.stat().st_ino
        seen.append(fd)
        return SimpleNamespace(f_bavail=free, f_frsize=1024 * 1024)
    monkeypatch.setattr(module, "os", SimpleNamespace(**{**vars(os), "statvfs": disk}))
    for _ in range(2):
        assert observations(run(root))["disk"] == {
            "state": state, "free_bytes": free * 1024 * 1024, "floor_mib": 4096}
    assert len(seen) == 2
    for fd in seen:
        with pytest.raises(OSError):
            os.fstat(fd)


def test_statvfs_error_does_not_hide_other_observations(tmp_path, monkeypatch, services):
    root = make_store(tmp_path)
    def failed(fd):
        raise OSError("TOKEN=secret")
    monkeypatch.setattr(module, "os", SimpleNamespace(**{**vars(os), "statvfs": failed}))
    rows = observations(run(root))
    assert rows["disk"] == {"state": "unknown", "reason": "disk_unavailable"}
    assert rows["audit"]["state"] == "clean"
    assert rows["capacity"]["state"] == "available"


def test_unsupported_disk_probe_is_portable(tmp_path, monkeypatch, services):
    monkeypatch.setattr(module, "disk_supported", lambda: False)
    assert observations(run(tmp_path))["disk"] == {"state": "unknown", "reason": "unsupported_platform"}


def test_unsupported_descriptor_probe_is_portable(tmp_path, monkeypatch, services):
    monkeypatch.setattr(module, "descriptor_supported", lambda: False)
    rows = observations(run(tmp_path))
    assert rows["writer_dead"]["leases"] == {"state": "unknown", "reason": "unsupported_platform"}
    assert rows["audit"] == {"state": "unknown", "reason": "unsupported_platform"}
    assert rows["capacity"]["state"] == "available"


@pytest.mark.parametrize("used,state", [(0, "available"), (98, "available"), (99, "at_limit"), (100, "at_limit")])
def test_capacity_and_usage_share_one_bounded_snapshot(tmp_path, services, used, state):
    reader = adapter(used)
    body = profile()
    before = deepcopy(body)
    for _ in range(2):
        rows = observations(run(tmp_path, body, reader))
        assert rows["capacity"]["state"] == state
        assert rows["usage"]["state"] == "known"
        assert rows["usage"]["hosts"][0]["usage"]["window"]["used_pct"] == used
    assert reader.calls == [("primary", "subscription-window")] * 2
    assert body == before


@pytest.mark.parametrize("credits,state", [(10, "available"), (0, "at_limit")])
def test_credits_capacity(tmp_path, services, credits, state):
    reader = team_hosts.FakeUsageAdapter({"primary": {"credits_left": credits}})
    rows = observations(run(tmp_path, profile("credits"), reader))
    assert rows["capacity"]["state"] == state
    assert rows["usage"]["hosts"][0]["usage"] == {"credits_left": credits}


@pytest.mark.parametrize("source", ["none", "missing", "bad", "raises"])
def test_missing_disabled_or_bad_usage_never_healthy(tmp_path, services, source):
    body = profile("none") if source == "none" else profile()
    value = {"bad": {"window": {"used_pct": float("nan"), "resets_at": "bad"}},
             "raises": RuntimeError("TOKEN=secret")}.get(source, {})
    reader = team_hosts.FakeUsageAdapter({"primary": value})
    rows = observations(run(tmp_path, body, reader))
    assert rows["capacity"]["state"] == rows["usage"]["state"] == "unknown"
    assert "secret" not in repr(rows)
    if source == "none":
        assert not reader.calls


def test_host_failure_retains_other_host_and_other_observations(tmp_path, services):
    reader = adapter(pair=True)
    reader.snapshots["primary"] = RuntimeError("TOKEN=secret")
    rows = observations(run(tmp_path, profile(pair=True), reader))
    assert rows["usage"]["state"] == rows["capacity"]["state"] == "unknown"
    assert rows["usage"]["hosts"][0]["state"] == "unknown"
    assert rows["usage"]["hosts"][1]["state"] == "known"


@pytest.mark.parametrize("case,state", [("clean", "clean"), ("findings", "findings"),
                                        ("refused", "unknown"), ("unreadable", "unknown")])
def test_audit_service_failure_matrix(tmp_path, monkeypatch, services, case, state):
    root = make_store(tmp_path)
    def audit(root, **kwargs):
        if case == "unreadable":
            raise PermissionError("TOKEN=secret")
        return {"status": "refused" if case == "refused" else "done", "exit_code": 0,
                "refused": case == "refused", "items": [],
                "findings": [{"reason": "TOKEN=secret\n"}] if case == "findings" else []}
    monkeypatch.setattr(team_queue, "audit", audit)
    for _ in range(2):
        rows = observations(run(root))
        assert rows["audit"]["state"] == state
        assert "secret" not in repr(rows)
        assert rows["capacity"]["state"] == "available"


def test_caps_reject_service_containers_before_iteration(tmp_path, monkeypatch, services):
    root = make_store(tmp_path)
    class OverCap(list):
        def __iter__(self):
            pytest.fail("oversized container was iterated")
    def audit(root, **kwargs):
        return {"status": "done", "refused": False, "exit_code": 0, "items": [],
                "findings": OverCap([None] * 2049)}
    monkeypatch.setattr(team_queue, "audit", audit)
    rows = observations(run(root))
    assert rows["audit"]["state"] == "unknown"


@pytest.mark.parametrize("now", [True, -1, 10**12, "TOKEN=secret"])
def test_invalid_clock_has_fixed_refusal(tmp_path, now):
    assert run(tmp_path, now=now) == {
        "schema": "aegis.team.supervisor.observations/v1", "status": "refused",
        "code": "invalid_clock", "reason": "invalid observation clock",
        "starts_nothing": True, "writes_nothing": True,
    }


def test_invalid_profile_has_fixed_refusal(tmp_path):
    result = run(tmp_path, {"profile": {"TOKEN=secret": []}})
    assert result["status"] == "refused" and result["code"] == "invalid_profile"
    assert result["reason"] == "invalid resolved observation profile"
    assert "secret" not in repr(result)


def test_concurrent_observers_do_not_share_snapshots_or_write(tmp_path, services):
    root = make_store(tmp_path)
    before = sorted(root.rglob("*"))
    def call(used):
        return observations(run(root, reader=adapter(used)))["capacity"]["state"]
    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(call, used) for used in (0, 99, 10, 100, 20, 100)]
        assert [f.result(timeout=5) for f in futures] == [
            "available", "at_limit", "available", "at_limit", "available", "at_limit"]
    assert sorted(root.rglob("*")) == before


def test_adapter_cannot_change_validated_policy_mid_observation(tmp_path, services):
    root = make_store(tmp_path)
    body = profile()
    class Reader:
        def read(self, host, source):
            body["profile"].clear()
            return {"window": {"used_pct": 10, "resets_at": "2026-11-16T00:00:00Z"}}
    rows = observations(run(root, body, Reader()))
    assert rows["capacity"]["state"] == "available"
    if module.disk_supported():
        assert rows["disk"]["floor_mib"] == 4096


def test_service_timeout_is_unknown_then_retry_recovers(tmp_path, monkeypatch, services):
    root = make_store(tmp_path)
    calls = []
    def audit(root, **kwargs):
        calls.append(None)
        if len(calls) == 1:
            raise TimeoutError("TOKEN=secret")
        return {"status": "done", "refused": False, "exit_code": 0, "items": [], "findings": []}
    monkeypatch.setattr(team_queue, "audit", audit)
    first = observations(run(root))
    assert first["audit"] == {"state": "unknown", "reason": "audit_unavailable"}
    assert first["usage"]["state"] == "known"
    assert observations(run(root))["audit"] == {"state": "clean", "findings": 0}


def test_all_borrowed_descriptors_close_on_service_and_disk_errors(tmp_path, monkeypatch, services):
    root = make_store(tmp_path)
    opened = []
    original = storage_confined.confined_file
    @contextmanager
    def tracked(*args, **kwargs):
        with original(*args, **kwargs) as handle:
            opened.append(handle._parent)
            yield handle
    def failed(*args, **kwargs):
        raise OSError("TOKEN=secret")
    monkeypatch.setattr(module, "storage_confined", SimpleNamespace(
        **{**vars(storage_confined), "confined_file": tracked}))
    monkeypatch.setattr(module, "os", SimpleNamespace(**{**vars(os), "statvfs": failed}))
    monkeypatch.setattr(team, "read_leases", failed)
    monkeypatch.setattr(team_queue, "audit", failed)
    rows = observations(run(root))
    assert all(rows[name]["state"] == "unknown" for name in ("writer_dead", "disk", "audit"))
    assert rows["capacity"]["state"] == "available"
    assert opened
    for fd in opened:
        with pytest.raises(OSError):
            os.fstat(fd)


@pytest.mark.parametrize("root", [None, "", "relative", "/../bad", "/bad\x00", "x" * 32769],
                         ids=["none", "empty", "relative", "parent", "nul", "oversized"])
def test_invalid_roots_never_echo_input_or_hide_hosts(services, root):
    rows = observations(run(root))
    assert rows["writer_dead"]["leases"]["state"] == "unknown"
    assert rows["audit"]["state"] == "unknown"
    assert rows["usage"]["state"] == "known"


def test_host_service_failure_does_not_hide_workspace(tmp_path, monkeypatch, services):
    root = make_store(tmp_path)
    def failed(*args, **kwargs):
        raise RuntimeError("TOKEN=secret")
    monkeypatch.setattr(team_hosts, "HostCapacity", failed)
    rows = observations(run(root))
    assert rows["usage"] == {"state": "unknown", "reason": "usage_unavailable"}
    assert rows["audit"]["state"] == "clean"


def test_oversized_lease_set_is_unknown(tmp_path, monkeypatch, services):
    root = make_store(tmp_path)
    found = team.LeaseSet((lease(),) * 257)
    monkeypatch.setattr(team, "read_leases", lambda root: found)
    assert observations(run(root))["writer_dead"]["leases"] == {
        "state": "unknown", "reason": "leases_unavailable"}


def test_capability_probe_failure_is_unknown_not_a_raw_exception(tmp_path, monkeypatch, services):
    root = make_store(tmp_path)
    def failed():
        raise OSError("TOKEN=secret")
    monkeypatch.setattr(module, "disk_supported", failed)
    rows = observations(run(root))
    assert rows["disk"] == {"state": "unknown", "reason": "disk_unavailable"}
    assert rows["audit"]["state"] == "clean"


def test_descriptor_probe_failure_keeps_host_observations(tmp_path, monkeypatch, services):
    def failed():
        raise OSError("TOKEN=secret")
    monkeypatch.setattr(module, "descriptor_supported", failed)
    rows = observations(run(tmp_path))
    assert rows["writer_dead"]["leases"]["state"] == "unknown"
    assert rows["usage"]["state"] == "known"


def test_real_services_only_launch_read_only_gitsafe_and_preserve_bytes(tmp_path, monkeypatch):
    root = make_store(tmp_path)
    subprocess.run(["git", "init", "-q", str(root)], check=True, timeout=10)
    calls = []
    original = gitsafe.run
    def read_only(args, *args_rest, **kwargs):
        assert args[0] in {"rev-parse", "check-ref-format", "for-each-ref", "cat-file"}
        calls.append(tuple(args))
        return original(args, *args_rest, **kwargs)
    monkeypatch.setattr(gitsafe, "run", read_only)
    before = {p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()}
    for _ in range(2):
        rows = observations(run(root))
        assert rows["audit"] == {"state": "clean", "findings": 0}
        assert rows["writer_dead"]["leases"]["state"] == "known"
    after = {p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()}
    assert before == after and calls


@pytest.mark.parametrize("case", ["symlink", "unreadable"])
def test_real_lease_records_never_prove_liveness(tmp_path, case):
    root = make_store(tmp_path)
    subprocess.run(["git", "init", "-q", str(root)], check=True, timeout=10)
    raw = json.dumps({"v": 1, "lane": "writer", "role": "implementer", "owner": "owner",
                      "claim_id": "a" * 16, "gen": 1, "branch": "lane/writer",
                      "paths": ["docs/**"], "ts": 50, "ttl_s": 100}).encode()
    result = subprocess.run(["git", "hash-object", "-w", "--stdin"], cwd=root,
                            input=raw if case == "symlink" else b"{", capture_output=True,
                            check=True, timeout=10)
    ref = root / ".git" / "refs" / "aegis" / "lanes" / "writer"
    ref.parent.mkdir(parents=True)
    if case == "symlink":
        outside = tmp_path / "ref-target"
        outside.write_bytes(result.stdout)
        symlink_or_skip(ref, outside)
    else:
        ref.write_bytes(result.stdout)
    for _ in range(2):
        row = observations(run(root))["writer_dead"]
        assert row["state"] == "unknown" and row["reason"] == "no_bound_liveness_source"
        # Lease facts retain the public Git reader's semantics. A readable ref
        # still proves no actor identity; a malformed blob stays unreadable.
        assert row["leases"] == {"state": "known" if case == "symlink" else "unknown",
                                 "live": int(case == "symlink"), "expired": 0,
                                 "unreadable": int(case == "unreadable")}


def assert_git_unknown(result, reason):
    rows = observations(result)
    assert rows["writer_dead"]["leases"] == {"state": "unknown", "reason": reason}
    assert rows["audit"] == {"state": "unknown", "reason": reason}
    assert rows["usage"]["state"] == "known"


def test_real_lease_limit_precedes_both_services_and_is_rechecked(tmp_path, monkeypatch):
    root = make_store(tmp_path)
    subprocess.run(["git", "init", "-q", str(root)], check=True, timeout=10)
    result = subprocess.run(["git", "hash-object", "-w", "--stdin"], cwd=root,
                            input=b"{}", capture_output=True, check=True, timeout=10)
    refs = root / ".git" / "refs" / "aegis" / "lanes"
    refs.mkdir(parents=True)
    for index in range(257):
        (refs / ("writer-" + str(index))).write_bytes(result.stdout)
    calls = []
    def leases(root):
        calls.append("leases")
        return team.LeaseSet()
    def audit(root, **kwargs):
        calls.append("audit")
        return {"status": "done", "refused": False, "exit_code": 0, "items": [], "findings": []}
    monkeypatch.setattr(team, "read_leases", leases)
    monkeypatch.setattr(team_queue, "audit", audit)
    assert_git_unknown(run(root), "lease_limit")
    assert calls == []
    (refs / "writer-256").unlink()
    assert observations(run(root))["audit"]["state"] == "clean"
    assert calls == ["leases", "audit"]


def test_normal_git_has_one_bounded_preflight_per_observation(tmp_path, monkeypatch):
    root = make_store(tmp_path)
    subprocess.run(["git", "init", "-q", str(root)], check=True, timeout=10)
    calls = []
    original = gitsafe.run
    def tracked(args, *rest, **kwargs):
        calls.append(tuple(args))
        return original(args, *rest, **kwargs)
    monkeypatch.setattr(gitsafe, "run", tracked)
    for _ in range(2):
        assert observations(run(root))["audit"]["state"] == "clean"
    counted = [args for args in calls if any(arg.startswith("--count=") for arg in args)]
    assert counted == [("for-each-ref", "--count=257", "--format=x", "refs/aegis/lanes/")] * 2


@pytest.mark.parametrize("case", ["timeout", "malformed", "oversized", "missing"])
def test_bad_bounded_preflight_never_reaches_services(tmp_path, monkeypatch, services, case):
    root = make_store(tmp_path)
    calls = []
    def counted(*args, **kwargs):
        calls.append("count")
        if case == "timeout":
            raise TimeoutError("TOKEN=secret")
        return SimpleNamespace(stdout={"malformed": b"TOKEN=secret\n", "oversized": b"x\n" * 258,
                                       "missing": None}[case])
    def unexpected(*args, **kwargs):
        pytest.fail("invalid preflight reached a service")
    monkeypatch.setattr(gitsafe, "run_checked", counted)
    monkeypatch.setattr(team, "read_leases", unexpected)
    monkeypatch.setattr(team_queue, "audit", unexpected)
    for _ in range(2):
        result = run(root)
        assert_git_unknown(result, "leases_unavailable")
        assert "secret" not in repr(result)
    assert calls == ["count", "count"]
