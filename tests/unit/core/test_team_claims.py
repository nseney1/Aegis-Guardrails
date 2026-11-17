"""Recoverable unclaim transitions through the public queue service."""
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import shlex
import shutil
import subprocess
from threading import Event
import time
from types import SimpleNamespace

import pytest

from conftest import symlink_or_skip
from aegis_core import events, gitsafe, storage, team, team_claims, team_queue as queue
from aegis_core import team_writer_binding as binding
from aegis_core.workspace.binding import resolve_cli_root


@pytest.fixture
def make_store(tmp_path):
    if not queue.descriptor_supported():
        pytest.skip("requires descriptor-relative nofollow operations")
    if shutil.which("git") is None:
        pytest.skip("requires git")
    root = tmp_path / "repo"
    root.mkdir()
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    (root / ".aegis").mkdir()
    (root / ".aegis" / "team.json").write_text(json.dumps({
        "v": 1, "lanes": {"alpha": ["src/**"], "beta": ["docs/**"]}}), encoding="utf-8")
    home = tmp_path / "home"
    home.mkdir()
    os.environ.update(HOME=str(home), USERPROFILE=str(home))
    return root


def held(root):
    added = queue.add(root, {"id": "ONE", "title": "Work", "paths": ["src/**"], "capabilities": []}, now=100)
    claimed = queue.claim(root, "ONE", expect=added["item"]["revision"], lane="alpha", now=101, caller="owner")
    assert not claimed["refused"], claimed
    lease = team.claim(root, "alpha", ["src/**"], owner="owner", now=100)
    return claimed["item"]["revision"], lease.oid


def unclaim(root, revision, **kwargs):
    return queue.unclaim(root, "ONE", expect=revision, lane=kwargs.pop("lane", "alpha"),
                         now=kwargs.pop("now", 102), caller="owner", writer_stopped=True, **kwargs)


def receipts(root):
    return [row for row in events.read(root).rows if row["detail"].get("action") == "unclaim"]


@pytest.fixture
def binding_home(make_store, monkeypatch):
    home = make_store.parent / "passwd-home"
    (home / ".config/aegis").mkdir(parents=True)
    monkeypatch.setattr(team_claims, "pwd", SimpleNamespace(
        getpwuid=lambda uid: SimpleNamespace(pw_dir=str(home))))
    return str(home)


def linked_writer(root):
    """Create history only inside this disposable repository, not the checkout."""
    subprocess.run(["git", "-C", str(root), "-c", "user.name=Test", "-c", "user.email=test@example.com",
                    "-c", "commit.gpgsign=false", "commit", "--allow-empty", "-qm", "Test root"],
                   check=True, capture_output=True, timeout=15)
    linked = root.parent / "linked-writer"
    subprocess.run(["git", "-C", str(root), "worktree", "add", "--detach", str(linked), "HEAD"],
                   check=True, capture_output=True, timeout=15)
    (linked / ".aegis").mkdir()
    return linked


@pytest.mark.parametrize("recovering", [False, True])
@pytest.mark.parametrize("shape", ["depth-129", "depth-256", "cr", "lf", "crlf"])
def test_unclaim_preserves_queue_workspace_contract(make_store, binding_home, monkeypatch, recovering, shape):
    if recovering:
        revision, _, _ = plant_pending(make_store, monkeypatch)
    else:
        revision, _ = held(make_store)
    if shape.startswith("depth-"):
        depth = int(shape.split("-")[1])
        root = make_store.parent.joinpath(*(["d"] * (depth - str(make_store.parent).count("/"))))
        root.parent.mkdir(parents=True)
        assert str(root).count("/") == depth
    else:
        root = make_store.with_name("workspace" + {"cr": "\r", "lf": "\n", "crlf": "\r\n"}[shape] + "name")
    make_store.rename(root)
    assert queue.valid_workspace_spelling(str(root))
    assert not (Path(binding_home) / ".config/aegis" / binding.NAME).exists()
    result = unclaim(root, revision)
    assert result["exit_code"] == 0 and result["item"]["state"] == "queued", result
    assert team.read_leases(root).get("alpha") is None
    assert len(receipts(root)) == 1
    assert "unclaim" not in json.loads((root / ".aegis/state/team-queue.json").read_bytes())


@pytest.mark.parametrize("recovering", [False, True])
@pytest.mark.parametrize("depth", [128, 129, 256, 257, 258])
def test_unclaim_preserves_queue_common_directory_contract(make_store, binding_home, monkeypatch, recovering, depth):
    if recovering:
        revision, _, _ = plant_pending(make_store, monkeypatch)
    else:
        revision, _ = held(make_store)
    common = make_store.parent.joinpath(*(["g"] * (depth - str(make_store.parent).count("/"))))
    common.parent.mkdir(parents=True)
    (make_store / ".git").rename(common)
    (make_store / ".git").write_text("gitdir: " + str(common) + "\n", encoding="utf-8")
    assert str(common).count("/") == depth
    assert gitsafe.common_dir(make_store) == common
    assert not (Path(binding_home) / ".config/aegis" / binding.NAME).exists()
    result = unclaim(make_store, revision)
    assert result["exit_code"] == 0 and result["item"]["state"] == "queued", result
    assert team.read_leases(make_store).get("alpha") is None
    assert len(receipts(make_store)) == 1
    assert "unclaim" not in json.loads((make_store / ".aegis/state/team-queue.json").read_bytes())


@pytest.mark.parametrize("shape", ["depth", "cr", "lf", "crlf"])
def test_binding_workspace_contract_remains_strict(make_store, binding_home, shape):
    if not binding.descriptor_supported():
        pytest.skip("requires Linux process identity and confined storage")
    if shape == "depth":
        root = make_store.parent.joinpath(*(["d"] * (129 - str(make_store.parent).count("/"))))
    else:
        root = make_store.with_name("workspace" + {"cr": "\r", "lf": "\n", "crlf": "\r\n"}[shape] + "name")
    result = binding.bind(binding_home, root, "alpha", os.getpid())
    assert result == {"status": "refused", "code": "state_unavailable", "reason": "unsafe or unreadable writer binding"}
    assert not root.exists() and not (Path(binding_home) / ".config/aegis" / binding.NAME).exists()


def test_binding_common_directory_contract_remains_strict(make_store, binding_home):
    if not binding.descriptor_supported():
        pytest.skip("requires Linux process identity and confined storage")
    _, oid = held(make_store)
    common = make_store.parent.joinpath(*(["g"] * (129 - str(make_store.parent).count("/"))))
    common.parent.mkdir(parents=True)
    (make_store / ".git").rename(common)
    (make_store / ".git").write_text("gitdir: " + str(common) + "\n", encoding="utf-8")
    result = binding.bind(binding_home, make_store, "alpha", os.getpid())
    assert result == {"status": "refused", "code": "lease_unavailable", "reason": "writer lease is unavailable"}
    assert team.read_leases(make_store).get("alpha").oid == oid
    assert not (Path(binding_home) / ".config/aegis" / binding.NAME).exists()


@pytest.mark.parametrize("linked", [False, True])
@pytest.mark.parametrize("recovering", [False, True])
def test_binding_publication_cannot_cross_final_unclaim_check(make_store, binding_home, monkeypatch, recovering, linked):
    if not binding.descriptor_supported():
        pytest.skip("requires Linux process identity and confined storage")
    if recovering:
        revision, oid, _ = plant_pending(make_store, monkeypatch)
    else:
        revision, oid = held(make_store)
    writer_root = linked_writer(make_store) if linked else make_store
    saved = team.read_leases(make_store).get("alpha")
    ready, permit, finished = Event(), Event(), Event()
    trace, timeouts = [], []
    publish_binding, publish_queue = binding._publish_leaf, queue.atomic_write_bytes

    def paused_binding(directory, data):
        trace.append("binding_selected_lease")
        ready.set()
        if not permit.wait(timeout=10):
            timeouts.append("binding_publication_barrier")
            raise AssertionError("binding publication barrier timed out")
        publish_binding(directory, data)
        trace.append("binding_published")

    def after_final_check(path, data, **kwargs):
        state = json.loads(data)
        if state["items"]["ONE"]["state"] == "queued":
            trace.append("unclaim_final_check_passed")
            permit.set()
            if not finished.wait(timeout=5):
                timeouts.append("binding_completion_barrier")
                raise AssertionError("binding completion barrier timed out")
            trace.append("unclaim_final_write")
        return publish_queue(path, data, **kwargs)

    def bind_writer():
        try:
            return binding.bind(binding_home, writer_root, "alpha", os.getpid())
        finally:
            finished.set()

    def bounded_workspace_lock(root, timeout):
        # A correct shared workspace exclusion may refuse while bind is paused.
        return storage.locked(root, timeout=0.5)

    monkeypatch.setattr(binding, "_publish_leaf", paused_binding)
    monkeypatch.setattr(queue, "atomic_write_bytes", after_final_check)
    monkeypatch.setattr(queue, "locked", bounded_workspace_lock)
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(bind_writer)
        try:
            assert ready.wait(timeout=5), "binding did not reach its publication boundary"
            released = unclaim(make_store, revision)
        finally:
            permit.set()
        bound = pending.result(timeout=10)
    assert timeouts == [], (timeouts, trace)
    if bound["status"] == "ok" and released["exit_code"] == 0:
        assert trace == ["binding_selected_lease", "unclaim_final_check_passed",
                         "binding_published", "unclaim_final_write"], trace
        assert team.read_leases(make_store).get("alpha") is None
        assert saved.oid == oid
        assert binding.judge(binding_home, team.LeaseSet((saved,), ()), {})["reason"] == "writer_bound"
    assert not (bound["status"] == "ok" and released["exit_code"] == 0), {
        "bind": bound, "unclaim": released, "trace": trace, "recovering": recovering}


@pytest.mark.parametrize("recovering", [False, True])
def test_binding_refuses_while_unclaim_holds_final_publication(make_store, binding_home, monkeypatch, recovering):
    if not binding.descriptor_supported():
        pytest.skip("requires Linux process identity and confined storage")
    if recovering:
        revision, _, _ = plant_pending(make_store, monkeypatch)
    else:
        revision, _ = held(make_store)
    ready, permit = Event(), Event()
    original = queue.atomic_write_bytes

    def pause_final(path, data, **kwargs):
        if json.loads(data)["items"]["ONE"]["state"] == "queued":
            ready.set()
            assert permit.wait(timeout=10), "unclaim final-publication barrier timed out"
        return original(path, data, **kwargs)

    monkeypatch.setattr(queue, "atomic_write_bytes", pause_final)
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(unclaim, make_store, revision)
        try:
            assert ready.wait(timeout=5), "unclaim did not reach final publication"
            result = binding.bind(binding_home, make_store, "alpha", os.getpid())
            assert (result["status"], result.get("code")) == ("refused", "state_locked"), result
        finally:
            permit.set()
        assert pending.result(timeout=10)["exit_code"] == 0
    retried = binding.bind(binding_home, make_store, "alpha", os.getpid())
    assert (retried["status"], retried["code"]) == ("refused", "lease_unavailable"), retried
    assert binding.load(binding_home) == {}


@pytest.mark.parametrize("linked", [False, True])
@pytest.mark.parametrize("recovering", [False, True])
def test_binding_judgements_share_the_workspace_exclusion(make_store, binding_home, monkeypatch, recovering, linked):
    if not binding.descriptor_supported():
        pytest.skip("requires Linux process identity and confined storage")
    if recovering:
        revision, _, _ = plant_pending(make_store, monkeypatch)
    else:
        revision, _ = held(make_store)
    writer_root = linked_writer(make_store) if linked else make_store
    original, attempts = binding.judge, []
    with ThreadPoolExecutor(max_workers=1) as pool:
        def checked(home, found, summary):
            attempt = pool.submit(binding.bind, binding_home, writer_root, "alpha", os.getpid())
            attempts.append(attempt.result(timeout=5))
            return original(home, found, summary)
        monkeypatch.setattr(binding, "judge", checked)
        result = unclaim(make_store, revision)
    assert attempts and all((row["status"], row.get("code")) == ("refused", "state_locked") for row in attempts), attempts
    assert result["exit_code"] == 0, result


def test_binding_workspace_lock_symlink_cannot_redirect_or_publish(make_store, binding_home, tmp_path):
    if not binding.descriptor_supported():
        pytest.skip("requires Linux process identity and confined storage")
    held(make_store)
    lock = make_store / ".aegis/state/lock"
    outside = tmp_path / "outside-lock"
    outside.write_bytes(b"KEEP")
    lock.unlink()
    symlink_or_skip(outside, lock)
    result = binding.bind(binding_home, make_store, "alpha", os.getpid())
    assert (result["status"], result.get("code")) == ("refused", "lease_unavailable"), result
    assert outside.read_bytes() == b"KEEP" and binding.load(binding_home) == {}


def test_binding_common_lock_symlink_refuses_without_redirect_and_retries(make_store, binding_home, tmp_path):
    if not binding.descriptor_supported():
        pytest.skip("requires Linux process identity and confined storage")
    revision, oid = held(make_store)
    path = make_store / ".aegis/state/team-queue.json"
    before = path.read_bytes()
    common = gitsafe.common_dir(make_store)
    lock = common / "aegis-writer.lock"
    outside = tmp_path / "outside-common-lock"
    outside.write_bytes(b"KEEP")
    symlink_or_skip(outside, lock)
    refused = binding.bind(binding_home, make_store, "alpha", os.getpid())
    assert (refused["status"], refused.get("code")) == ("refused", "lease_unavailable"), refused
    result = unclaim(make_store, revision)
    assert (result["reason"], result["exit_code"]) == ("queue_io_unavailable", 1), result
    assert path.read_bytes() == before and team.read_leases(make_store).get("alpha").oid == oid
    assert outside.read_bytes() == b"KEEP" and binding.load(binding_home) == {}
    lock.unlink()
    assert unclaim(make_store, revision)["exit_code"] == 0


def test_binding_indeterminate_git_layout_cannot_skip_exclusion(make_store, binding_home, monkeypatch):
    if not binding.descriptor_supported():
        pytest.skip("requires Linux process identity and confined storage")
    revision, oid = held(make_store)
    path = make_store / ".aegis/state/team-queue.json"
    before = path.read_bytes()
    monkeypatch.setattr(binding, "gitsafe", SimpleNamespace(**{**vars(gitsafe), "common_dir": lambda root: None}))
    result = binding.bind(binding_home, make_store, "alpha", os.getpid())
    assert (result["status"], result.get("code")) == ("refused", "lease_unavailable"), result
    result = unclaim(make_store, revision)
    assert (result["reason"], result["exit_code"]) == ("queue_io_unavailable", 1), result
    assert path.read_bytes() == before and team.read_leases(make_store).get("alpha").oid == oid
    assert binding.load(binding_home) == {}
    monkeypatch.setattr(binding, "gitsafe", gitsafe)
    assert unclaim(make_store, revision)["exit_code"] == 0


@pytest.mark.parametrize("kind", ["worktree", "subdirectory", "bare"])
def test_binding_indeterminate_exclusion_refuses_all_git_layouts(make_store, monkeypatch, kind):
    root = make_store
    if kind == "subdirectory":
        root = make_store / "subdirectory"
        root.mkdir()
    elif kind == "bare":
        root = make_store.parent / "bare"
        subprocess.run(["git", "init", "--bare", "-q", str(root)], check=True, capture_output=True, timeout=15)
    monkeypatch.setattr(binding, "gitsafe", SimpleNamespace(**{**vars(gitsafe), "common_dir": lambda root: None}))
    with pytest.raises(binding.BindingLockRefused, match="^writer lease is unavailable$") as refused:
        with binding.claim_exclusion(root):
            pytest.fail("indeterminate Git layout admitted without exclusion")
    assert refused.value.code == "lease_unavailable"


def test_binding_unsupported_platform_refuses_before_creating_locks(tmp_path, monkeypatch):
    home, workspace = tmp_path / "missing-home", tmp_path / "missing-workspace"
    monkeypatch.setattr(binding, "descriptor_supported", lambda: False)
    assert binding.bind(str(home), str(workspace), "alpha", os.getpid()) == {
        "status": "refused", "code": "unsupported_platform",
        "reason": "unsupported platform: writer binding unavailable"}
    assert not home.exists() and not workspace.exists()


def test_binding_shared_lock_contention_refuses_then_retries(make_store, binding_home):
    if not binding.descriptor_supported():
        pytest.skip("requires Linux process identity and confined storage")
    held(make_store)
    with ThreadPoolExecutor(max_workers=1) as pool:
        with storage.locked(make_store):
            result = pool.submit(binding.bind, binding_home, make_store, "alpha", os.getpid()).result(timeout=5)
        assert (result["status"], result.get("code")) == ("refused", "state_locked"), result
    assert binding.load(binding_home) == {}
    assert binding.bind(binding_home, make_store, "alpha", os.getpid()) == {"status": "ok"}


def test_binding_failed_publication_releases_exclusions_and_retries(make_store, binding_home, monkeypatch):
    if not binding.descriptor_supported():
        pytest.skip("requires Linux process identity and confined storage")
    held(make_store)

    def failed(directory, data):
        raise OSError("private-value")

    original = binding._publish_leaf
    monkeypatch.setattr(binding, "_publish_leaf", failed)
    try:
        result = binding.bind(binding_home, make_store, "alpha", os.getpid())
    finally:
        monkeypatch.setattr(binding, "_publish_leaf", original)
    assert (result["status"], result.get("code")) == ("refused", "state_unavailable"), result
    assert "private-value" not in json.dumps(result) and binding.load(binding_home) == {}
    assert binding.bind(binding_home, make_store, "alpha", os.getpid()) == {"status": "ok"}


@pytest.mark.parametrize("fault", ["missing-root", "invalid-state", "bad-caller", "bad-reason"])
@pytest.mark.parametrize("ack", [False, True])
def test_binding_absence_preserves_other_refusal_priorities(make_store, binding_home, fault, ack):
    revision, oid = held(make_store)
    path = make_store / ".aegis/state/team-queue.json"
    if fault == "invalid-state":
        path.write_bytes(b"{")
    before = path.read_bytes()
    root = make_store.parent / "missing-root" if fault == "missing-root" else make_store
    result = queue.unclaim(root, "ONE", expect=revision, lane="alpha", now=102, writer_stopped=ack,
                           caller="private-value\ncaller" if fault == "bad-caller" else "owner",
                           reason="bad\nreason" if fault == "bad-reason" else "Waiting")
    expected = "writer_not_stopped" if not ack else {
        "missing-root": "queue_io_unavailable", "invalid-state": "invalid_queue_state",
        "bad-caller": "invalid_arguments", "bad-reason": "invalid_item"}[fault]
    assert result["reason"] == expected and result["exit_code"] == (2 if expected in ("invalid_arguments", "invalid_item") else 1), result
    assert path.read_bytes() == before and team.read_leases(make_store).get("alpha").oid == oid
    assert "private-value" not in json.dumps(result)


@pytest.mark.parametrize("source", ["missing-directory", "missing-binding", "live"])
@pytest.mark.parametrize("ack", [False, True])
@pytest.mark.parametrize("defect", ["bad-reason", "stale-revision"])
def test_binding_combined_failure_precedence(make_store, binding_home, source, ack, defect):
    revision, oid = held(make_store)
    if source == "live":
        if not binding.descriptor_supported():
            pytest.skip("requires Linux process identity and confined storage")
        assert binding.bind(binding_home, make_store, "alpha", os.getpid())["status"] == "ok"
    elif source == "missing-directory":
        (Path(binding_home) / ".config/aegis").rmdir()
    path = make_store / ".aegis/state/team-queue.json"
    before = path.read_bytes()
    result = queue.unclaim(make_store, "ONE", expect="0" * 64 if defect == "stale-revision" else revision,
                           lane="alpha", now=102, caller="owner", writer_stopped=ack,
                           reason="bad\nreason" if defect == "bad-reason" else "Waiting")
    assert path.read_bytes() == before and team.read_leases(make_store).get("alpha").oid == oid
    expected = ("writer_live" if source == "live" else "writer_not_stopped" if not ack else
                "invalid_item" if defect == "bad-reason" else "stale_revision")
    assert (result["reason"], result["exit_code"]) == (expected, 2 if expected == "invalid_item" else 1), result
    assert result["next_action"] == queue.refusal(expected, verb="unclaim")["next_action"]


@pytest.mark.parametrize("ack", [False, True])
@pytest.mark.parametrize("verdict", ["writer_bound", "no_bound_liveness_source", "identity_unavailable",
    "binding_scope_mismatch", "bindings_unavailable", "writer_absent", "writer_replaced"])
def test_binding_verdict_precedes_acknowledgement(make_store, binding_home, monkeypatch, ack, verdict):
    revision, oid = held(make_store)
    path = make_store / ".aegis/state/team-queue.json"
    before = path.read_bytes()
    calls = []

    def judge(home, found, summary):
        calls.append((home, found))
        return {"state": "dead" if verdict in ("writer_absent", "writer_replaced") else "unknown",
                "reason": verdict, "leases": summary}

    monkeypatch.setattr(binding, "judge", judge)
    result = queue.unclaim(make_store, "ONE", expect=revision, lane="alpha", now=102,
                           caller="owner", writer_stopped=ack)
    expected = ("writer_live" if verdict == "writer_bound" else
                "writer_not_stopped" if verdict == "no_bound_liveness_source" else verdict)
    if ack and verdict != "writer_bound":
        assert result["exit_code"] == 0 and result["item"]["state"] == "queued", result
    else:
        assert result["reason"] == expected and result["exit_code"] == 1, result
        assert path.read_bytes() == before and team.read_leases(make_store).get("alpha").oid == oid
        assert receipts(make_store) == []
    assert calls and all(found.get("alpha").oid == oid and len(found.leases) == 1 for _, found in calls)
    assert all(home == binding_home for home, _ in calls)
    assert all(str(home) != os.environ["HOME"] for home, _ in calls)


def test_binding_live_refusal_retries_and_concurrent_callers(make_store, monkeypatch):
    revision, oid = held(make_store)
    path = make_store / ".aegis/state/team-queue.json"
    before = path.read_bytes()
    monkeypatch.setattr(binding, "judge", lambda home, found, summary:
                        {"state": "unknown", "reason": "writer_bound", "leases": summary})
    with ThreadPoolExecutor(max_workers=2) as pool:
        pending = [pool.submit(unclaim, make_store, revision) for _ in range(2)]
        results = [future.result(timeout=15) for future in pending]
    results.append(unclaim(make_store, revision))
    assert all(row["reason"] == "writer_live" and row["exit_code"] == 1 for row in results), results
    assert path.read_bytes() == before and team.read_leases(make_store).get("alpha").oid == oid
    monkeypatch.setattr(binding, "judge", lambda home, found, summary:
                        {"state": "dead", "reason": "writer_absent", "leases": summary})
    assert unclaim(make_store, revision)["exit_code"] == 0
    assert len(receipts(make_store)) == 1


@pytest.mark.parametrize("phase", ["before-release", "after-release", "before-final-publication"])
def test_binding_appearing_during_unclaim_blocks_completion(make_store, monkeypatch, phase):
    revision, oid = held(make_store)
    path = make_store / ".aegis/state/team-queue.json"
    original = queue._publish
    before = path.read_bytes()
    live = [False]

    def judge(home, found, summary):
        assert found.get("alpha").oid == oid
        return {"state": "unknown", "reason": "writer_bound" if live[0] else "no_bound_liveness_source",
                "leases": summary}

    def publish(root, state, **kwargs):
        if (phase == "before-release" and "unclaim" in state) or (
                phase == "after-release" and state.get("unclaim", {}).get("released_lease_ids")) or "unclaim" not in state:
            live[0] = True
        return original(root, state, **kwargs)

    monkeypatch.setattr(binding, "judge", judge)
    monkeypatch.setattr(queue, "_publish", publish)
    result = unclaim(make_store, revision)
    assert result["reason"] == "writer_live" and result["exit_code"] == 1, result
    assert json.loads(path.read_bytes())["items"]["ONE"]["state"] == "claimed"
    if phase == "before-release":
        assert path.read_bytes() == before
        assert team.read_leases(make_store).get("alpha").oid == oid and receipts(make_store) == []
    else:
        assert "unclaim" in json.loads(path.read_bytes())
        assert team.read_leases(make_store).get("alpha") is None
    monkeypatch.setattr(queue, "_publish", original)
    live[0] = False
    assert unclaim(make_store, revision)["exit_code"] == 0
    assert len(receipts(make_store)) == 1


@pytest.mark.parametrize("released", [False, True])
def test_binding_live_blocks_pending_recovery(make_store, monkeypatch, released):
    revision, oid = held(make_store)
    original = queue._publish

    def crash(root, state, **kwargs):
        if (released and "unclaim" not in state) or (not released and "unclaim" in state):
            if not released:
                original(root, state, **kwargs)
            raise OSError("private-value")
        return original(root, state, **kwargs)

    monkeypatch.setattr(queue, "_publish", crash)
    assert unclaim(make_store, revision)["reason"] == "unclaim_recovery_required"
    monkeypatch.setattr(queue, "_publish", original)
    path = make_store / ".aegis/state/team-queue.json"
    before = path.read_bytes()
    monkeypatch.setattr(binding, "judge", lambda home, found, summary:
                        {"state": "unknown", "reason": "writer_bound", "leases": summary})
    for _ in range(2):
        result = unclaim(make_store, revision)
        assert result["reason"] == "writer_live" and result["exit_code"] == 1, result
        assert path.read_bytes() == before
    assert (team.read_leases(make_store).get("alpha") is None) is released
    monkeypatch.setattr(binding, "judge", lambda home, found, summary:
                        {"state": "dead", "reason": "writer_absent", "leases": summary})
    assert unclaim(make_store, revision)["exit_code"] == 0
    assert len(receipts(make_store)) == 1


@pytest.mark.parametrize("verdict", [None, {}, {"reason": []}, {"reason": "private-value\ntrailer"}])
def test_binding_malformed_verdict_is_typed_and_private(make_store, binding_home, monkeypatch, verdict):
    revision, oid = held(make_store)
    monkeypatch.setattr(binding, "judge", lambda *args: verdict)
    result = queue.unclaim(make_store, "ONE", expect=revision, lane="alpha", now=102, caller="owner")
    assert result["reason"] == "bindings_unavailable" and result["exit_code"] == 1, result
    assert "private-value" not in json.dumps(result) and "trailer" not in json.dumps(result)
    assert team.read_leases(make_store).get("alpha").oid == oid


def test_binding_real_live_identity_cannot_be_acknowledged(make_store, binding_home):
    if not binding.descriptor_supported():
        pytest.skip("requires Linux process identity and confined storage")
    revision, oid = held(make_store)
    assert binding.bind(binding_home, make_store, "alpha", os.getpid())["status"] == "ok"
    path = make_store / ".aegis/state/team-queue.json"
    before = path.read_bytes()
    for ack in (False, True, True):
        result = queue.unclaim(make_store, "ONE", expect=revision, lane="alpha", now=102,
                               caller="owner", writer_stopped=ack)
        assert result["reason"] == "writer_live" and result["exit_code"] == 1, result
        assert path.read_bytes() == before and team.read_leases(make_store).get("alpha").oid == oid
    assert receipts(make_store) == []


def test_binding_unrelated_live_writer_does_not_block_item(make_store, binding_home):
    if not binding.descriptor_supported():
        pytest.skip("requires Linux process identity and confined storage")
    revision, _ = held(make_store)
    unrelated = team.claim(make_store, "beta", ["docs/**"], owner="owner", now=100)
    assert binding.bind(binding_home, make_store, "beta", os.getpid())["status"] == "ok"
    assert unclaim(make_store, revision)["exit_code"] == 0
    assert team.read_leases(make_store).get("beta").oid == unrelated.oid


@pytest.mark.parametrize("ack", [False, True])
def test_binding_probe_unsupported_requires_explicit_ack(make_store, binding_home, monkeypatch, ack):
    revision, oid = held(make_store)
    monkeypatch.setattr(binding, "descriptor_supported", lambda: False)
    result = queue.unclaim(make_store, "ONE", expect=revision, lane="alpha", now=102,
                           caller="owner", writer_stopped=ack)
    if ack:
        assert result["exit_code"] == 0, result
    else:
        assert result["reason"] == "bindings_unavailable" and result["exit_code"] == 1, result
        assert team.read_leases(make_store).get("alpha").oid == oid


@pytest.mark.parametrize("case", ["absent", "symlink", "unreadable-home", "oversized", "malformed"])
def test_binding_storage_refusals_and_absence_are_distinct(make_store, binding_home, monkeypatch, case):
    revision, oid = held(make_store)
    home = Path(binding_home)
    config = home / ".config/aegis"
    if case in ("absent", "symlink"):
        config.rmdir()
        if case == "symlink":
            outside = make_store.parent / "outside"
            outside.mkdir()
            symlink_or_skip(outside, config, target_is_directory=True)
    elif case == "unreadable-home":
        def unavailable(uid):
            raise OSError("private-value")
        monkeypatch.setattr(team_claims, "pwd", SimpleNamespace(getpwuid=unavailable))
    else:
        (config / binding.NAME).write_bytes(b"x" * (binding.MAX_BYTES + 1) if case == "oversized" else b"{")
    result = queue.unclaim(make_store, "ONE", expect=revision, lane="alpha", now=102, caller="owner")
    assert result["reason"] == ("writer_not_stopped" if case == "absent" else "bindings_unavailable"), result
    assert result["exit_code"] == 1 and "private-value" not in json.dumps(result)
    assert team.read_leases(make_store).get("alpha").oid == oid
    assert unclaim(make_store, revision)["exit_code"] == 0


def test_unclaim_releases_intersecting_lease_and_records_once(make_store):
    revision, oid = held(make_store)
    unrelated = team.claim(make_store, "beta", ["docs/**"], owner="owner", now=100)
    before = queue.list(make_store, now=102)["claimable_fingerprint"]
    result = unclaim(make_store, revision, reason="Waiting for review")
    assert not result["refused"], result
    assert result["item"]["state"] == "queued" and result["released_lease_ids"] == [oid]
    assert team.read_leases(make_store).get("alpha") is None
    assert team.read_leases(make_store).get("beta").oid == unrelated.oid
    rows = receipts(make_store)
    assert len(rows) == 1
    assert rows[0]["detail"]["reason"] == "Waiting for review"
    assert rows[0]["detail"]["released_lease_ids"] == [oid]
    assert rows[0]["detail"]["lane"] == "alpha"
    assert rows[0]["detail"]["writer_stopped"] is True and rows[0]["detail"]["caller"] == "owner"
    assert queue.list(make_store, now=102)["claimable_fingerprint"] != before
    assert unclaim(make_store, revision)["reason"] == "stale_revision"
    assert len(receipts(make_store)) == 1


@pytest.mark.parametrize("case,reason", [("stale", "stale_revision"), ("lane", "lane_mismatch"),
                                        ("expired-lane", "lane_mismatch"), ("done", "item_done")])
def test_unclaim_refusals_preserve_queue_and_leases(make_store, case, reason):
    revision, oid = held(make_store)
    if case == "done":
        revision = queue.done(make_store, "ONE", expect=revision, lane="alpha", now=102)["item"]["revision"]
    path = make_store / ".aegis" / "state" / "team-queue.json"
    before = path.read_bytes()
    result = unclaim(make_store, "0" * 64 if case == "stale" else revision,
                     lane="beta" if "lane" in case else "alpha", now=10000 if case == "expired-lane" else 103)
    assert result["reason"] == reason and result["exit_code"] == 1
    assert path.read_bytes() == before and team.read_leases(make_store).get("alpha").oid == oid
    assert receipts(make_store) == []


@pytest.mark.parametrize("reason,code", [("token=private-value", "credential_like_text"),
    ("private-value\ntrailer", "invalid_item"), ("x" * (queue.MAX_TEXT + 1), "invalid_item")])
def test_unclaim_reason_is_bounded_single_line_and_private(make_store, reason, code):
    revision, oid = held(make_store)
    path = make_store / ".aegis" / "state" / "team-queue.json"
    before = path.read_bytes()
    result = unclaim(make_store, revision, reason=reason)
    assert result["reason"] == code and result["exit_code"] == 2
    assert "private-value" not in json.dumps(result)
    assert path.read_bytes() == before and team.read_leases(make_store).get("alpha").oid == oid


@pytest.mark.parametrize("case", ["foreign-owner", "foreign-lane", "unreadable"])
def test_unclaim_lease_preflight_refuses_without_changes(make_store, case):
    revision, oid = held(make_store)
    if case == "foreign-owner":
        team.transfer(make_store, "alpha", oid, owner="someone-else", now=102)
    elif case == "foreign-lane":
        team.release(make_store, "alpha", oid, caller="owner")
        team.claim(make_store, "beta", ["src/**"], owner="someone-else", now=100)
    else:
        bad = gitsafe.write_blob(make_store, b"{}")
        gitsafe.update_ref(make_store, team.lane_ref("alpha"), bad, oid)
    path = make_store / ".aegis" / "state" / "team-queue.json"
    before, refs = path.read_bytes(), gitsafe.list_refs(make_store, team.LANES_REF)
    for _ in range(2):
        result = unclaim(make_store, revision)
        assert result["reason"] == "unclaim_lease_refused" and result["exit_code"] == 1
        assert result["blockers"][0]["lease_oid"] and "aegis team release" in result["blockers"][0]["next_action"]
        assert path.read_bytes() == before and gitsafe.list_refs(make_store, team.LANES_REF) == refs


def test_unclaim_without_covering_lease_preserves_unrelated_lease(make_store):
    revision, oid = held(make_store)
    team.release(make_store, "alpha", oid, caller="owner")
    unrelated = team.claim(make_store, "alpha", ["docs/**"], owner="owner", now=100)
    result = unclaim(make_store, revision)
    assert not result["refused"] and result["released_lease_ids"] == []
    assert team.read_leases(make_store).get("alpha").oid == unrelated.oid


def test_unclaim_moved_oid_is_refused_before_any_change(make_store, monkeypatch):
    revision, oid = held(make_store)
    path = make_store / ".aegis" / "state" / "team-queue.json"
    before, original = path.read_bytes(), team_claims._release_lease

    def move_then_release(root, lane, expected, **kwargs):
        team.renew(root, lane, expected, now=102)
        return original(root, lane, expected, **kwargs)

    monkeypatch.setattr(team_claims, "_release_lease", move_then_release)
    result = unclaim(make_store, revision)
    assert result["reason"] == "unclaim_lease_refused" and result["exit_code"] == 1
    assert path.read_bytes() == before and team.read_leases(make_store).get("alpha").oid != oid
    assert receipts(make_store) == []


@pytest.mark.parametrize("phase", ["before-release", "after-release", "after-event"])
def test_crash_recovery_blocks_other_transitions_and_records_once(make_store, monkeypatch, phase):
    revision, _ = held(make_store)
    original_release, original_publish = team_claims._release_lease, queue._publish

    def crash_release(*args, **kwargs):
        if phase == "after-release":
            original_release(*args, **kwargs)
        raise OSError("private-value")

    def crash_publish(root, state, **kwargs):
        if "unclaim" not in state:
            raise OSError("private-value")
        return original_publish(root, state, **kwargs)

    if phase == "after-event":
        monkeypatch.setattr(queue, "_publish", crash_publish)
    else:
        monkeypatch.setattr(team_claims, "_release_lease", crash_release)
    result = unclaim(make_store, revision)
    monkeypatch.setattr(queue, "_publish", original_publish)
    monkeypatch.setattr(team_claims, "_release_lease", original_release)
    assert result["reason"] == "unclaim_recovery_required" and result["exit_code"] == 1
    assert "private-value" not in json.dumps(result) and "unclaim" in result["next_action"]
    for verb in ("claim", "release", "done"):
        result = getattr(queue, verb)(make_store, "ONE", expect=revision, lane="alpha", now=10000)
        assert result["reason"] == "unclaim_recovery_required"
    recovered = unclaim(make_store, revision)
    assert not recovered["refused"] and recovered["item"]["state"] == "queued"
    assert team.read_leases(make_store).get("alpha") is None and len(receipts(make_store)) == 1


def race_unclaim(arguments):
    return unclaim(*arguments)


def test_concurrent_unclaims_have_one_recorded_winner(make_store):
    revision, _ = held(make_store)
    with ProcessPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(race_unclaim, [(make_store, revision)] * 2, timeout=30))
    assert sorted(row["refused"] for row in results) == [False, True]
    assert next(row for row in results if row["refused"])["reason"] == "stale_revision"
    assert len(receipts(make_store)) == 1


def test_unclaim_unsupported_platform_is_fixed(tmp_path, monkeypatch):
    monkeypatch.setattr(queue, "descriptor_supported", lambda: False)
    result = unclaim(tmp_path, "0" * 64)
    assert result["reason"] == "unsupported_platform" and result["exit_code"] == 1


def test_oversized_receipt_log_refuses_before_releasing(make_store, monkeypatch):
    revision, oid = held(make_store)
    monkeypatch.setattr(team_claims, "MAX_EVENT_BYTES", 32)
    path = make_store / ".aegis" / "state" / "team-queue.json"
    before = path.read_bytes()
    result = unclaim(make_store, revision)
    assert result["reason"] == "unclaim_event_unavailable" and result["exit_code"] == 1
    assert path.read_bytes() == before and team.read_leases(make_store).get("alpha").oid == oid


def test_event_failure_after_release_can_be_retried(make_store, monkeypatch):
    revision, _ = held(make_store)
    monkeypatch.setattr(team_claims, "events", SimpleNamespace(**{**vars(events), "try_append": lambda *a, **kw: OSError("private-value")}))
    result = unclaim(make_store, revision)
    monkeypatch.setattr(team_claims, "events", events)
    assert result["reason"] == "unclaim_recovery_required" and "private-value" not in json.dumps(result)
    assert not unclaim(make_store, revision)["refused"]
    assert len(receipts(make_store)) == 1


@pytest.mark.parametrize("phase", ["before-publication", "after-publication"])
def test_intent_publication_failure_returns_recovery_step(make_store, monkeypatch, phase):
    revision, oid = held(make_store)
    original = queue._publish

    def failed(root, state, **kwargs):
        if phase == "after-publication":
            original(root, state, **kwargs)
        raise OSError("private-value")

    monkeypatch.setattr(queue, "_publish", failed)
    result = unclaim(make_store, revision)
    monkeypatch.setattr(queue, "_publish", original)
    assert result["reason"] == "unclaim_recovery_required" and result["exit_code"] == 1
    assert "private-value" not in json.dumps(result)
    assert team.read_leases(make_store).get("alpha").oid == oid
    assert not unclaim(make_store, revision)["refused"]
    assert len(receipts(make_store)) == 1


def test_symlink_receipt_log_refuses_without_echo_or_changes(make_store, tmp_path):
    revision, oid = held(make_store)
    outside = tmp_path / "private-value"
    outside.write_text("token=private-value", encoding="utf-8")
    log = events.events_path(make_store)
    log.rename(log.with_name("retained-events"))
    symlink_or_skip(outside, log)
    path = make_store / ".aegis" / "state" / "team-queue.json"
    before = path.read_bytes()
    result = unclaim(make_store, revision)
    assert result["reason"] == "unclaim_event_unavailable" and result["exit_code"] == 1
    assert "private-value" not in json.dumps(result)
    assert path.read_bytes() == before and team.read_leases(make_store).get("alpha").oid == oid


def test_fingerprint_changes_when_a_lease_expires(make_store):
    held(make_store)
    before = queue.list(make_store, now=102)["claimable_fingerprint"]
    after = queue.list(make_store, now=86500)["claimable_fingerprint"]
    assert before != after
    assert queue.list(make_store, now=86501)["claimable_fingerprint"] == after


def test_fingerprint_tracks_holds_leases_and_completion_without_clock_noise(make_store):
    revision, oid = held(make_store)
    fingerprint = lambda now=102: queue.list(make_store, now=now)["claimable_fingerprint"]
    initial = fingerprint()
    assert fingerprint(103) == initial
    team.release(make_store, "alpha", oid, caller="owner")
    freed = fingerprint()
    assert freed != initial
    queue.done(make_store, "ONE", expect=revision, lane="alpha", now=104)
    assert fingerprint() != freed
    added = queue.add(make_store, {"id": "TWO", "title": "Held", "paths": ["docs/**"],
        "capabilities": [], "hold_until": [{"kind": "milestone", "name": "landed"}]}, now=105)
    assert not added["refused"]
    held_fingerprint = fingerprint()
    path = make_store / ".aegis" / "state" / "team-queue.json"
    state = json.loads(path.read_text(encoding="utf-8"))
    state["milestones"] = ["landed"]
    path.write_text(json.dumps(state), encoding="utf-8")
    assert fingerprint() != held_fingerprint
    assert queue.list(make_store, capabilities=["other"], include_done=True, now=102)["claimable_fingerprint"] == fingerprint()


def test_operator_must_acknowledge_stopped_writer(make_store):
    revision, oid = held(make_store)
    path = make_store / ".aegis" / "state" / "team-queue.json"
    before = path.read_bytes()
    result = queue.unclaim(make_store, "ONE", expect=revision, lane="alpha", now=102, caller="owner")
    assert result["refused"] and result["reason"] == "writer_not_stopped"
    assert result["exit_code"] == 1 and "--writer-stopped" in result["next_action"]
    assert path.read_bytes() == before and team.read_leases(make_store).get("alpha").oid == oid


def test_recovery_keeps_intent_when_a_new_lane_lease_appears(make_store, monkeypatch):
    revision, oid = held(make_store)
    original = team_claims._release_lease

    def released_then_crashed(*args, **kwargs):
        original(*args, **kwargs)
        raise OSError("lost acknowledgement")

    monkeypatch.setattr(team_claims, "_release_lease", released_then_crashed)
    assert unclaim(make_store, revision)["reason"] == "unclaim_recovery_required"
    monkeypatch.setattr(team_claims, "_release_lease", original)
    newer = team.claim(make_store, "alpha", ["docs/**"], owner="owner", now=103)
    assert newer.oid != oid
    path = make_store / ".aegis" / "state" / "team-queue.json"
    before = path.read_bytes()
    result = unclaim(make_store, revision)
    assert result["reason"] == "unclaim_recovery_required"
    assert path.read_bytes() == before and "unclaim" in json.loads(before)


def test_event_capacity_is_checked_before_any_change(make_store, monkeypatch):
    revision, oid = held(make_store)
    monkeypatch.setattr(team_claims, "MAX_EVENT_BYTES", events.events_path(make_store).stat().st_size + 1)
    path = make_store / ".aegis" / "state" / "team-queue.json"
    before = path.read_bytes()
    result = unclaim(make_store, revision)
    assert result["reason"] == "unclaim_event_unavailable"
    assert path.read_bytes() == before and team.read_leases(make_store).get("alpha").oid == oid


def test_non_git_lease_free_hold_remains_unmet(make_store, tmp_path):
    result = queue.add(make_store, {"id": "ONE", "title": "Held", "paths": ["src/**"],
        "capabilities": [], "hold_until": [{"kind": "lease_free", "paths": ["src/**"]}]}, now=100)
    assert not result["refused"]
    (make_store / ".git").rename(tmp_path / "retained-git")
    os.environ["GIT_CEILING_DIRECTORIES"] = str(make_store.parent)
    assert gitsafe.run(["rev-parse", "--is-inside-work-tree"], make_store).returncode != 0
    listed = queue.list(make_store, now=102)
    assert not listed["refused"], listed
    assert listed["items"][0]["conditions_met"] is False
    assert listed["items"][0]["blockers"][0]["reason"] == "lease_free"


@pytest.mark.parametrize("case", ["capacity", "lane", "invalid-profile"])
def test_fingerprint_tracks_every_claim_policy_change(make_store, case):
    held(make_store)
    added = queue.add(make_store, {"id": "TWO", "title": "Work", "paths": ["docs/**"], "capabilities": []}, now=100)
    assert not added["refused"]
    profile = make_store / ".aegis" / "team" / "profile.json"
    profile.parent.mkdir(exist_ok=True)
    if case == "invalid-profile":
        profile.write_text("{}", encoding="utf-8")
    elif case == "lane":
        profile.write_text(json.dumps({"version": 1, "run_config": {"limits": {"writers_max": 2}}}), encoding="utf-8")
    lane = "gamma" if case == "lane" else "beta"
    result = queue.claim(make_store, "TWO", expect=added["item"]["revision"], lane=lane, now=102)
    assert result["reason"] == {"lane": "blocked", "capacity": "capacity_full", "invalid-profile": "profile_unavailable"}[case]
    before = queue.list(make_store, now=102)["claimable_fingerprint"]
    if case == "lane":
        config = make_store / ".aegis" / "team.json"
        value = json.loads(config.read_text())
        value["lanes"]["gamma"] = ["docs/**"]
        config.write_text(json.dumps(value), encoding="utf-8")
    else:
        profile.write_text(json.dumps({"version": 1, "run_config": {"limits": {"writers_max": 2}}}), encoding="utf-8")
    assert queue.list(make_store, now=102)["claimable_fingerprint"] != before
    assert not queue.claim(make_store, "TWO", expect=added["item"]["revision"], lane=lane, now=104)["refused"]


def mutate_lease(root, mutation):
    current = team.read_leases(root).get("alpha")
    if mutation in ("removed", "same-lane", "foreign") and current is not None:
        team.release(root, "alpha", current.oid, caller="external")
    if mutation == "same-lane":
        team.claim(root, "alpha", ["docs/**"], owner="owner", now=103)
    elif mutation == "foreign":
        team.claim(root, "beta", ["src/**"], owner="external", now=103)
    elif mutation == "unreadable":
        bad = gitsafe.write_blob(root, b"{}")
        gitsafe.update_ref(root, team.lane_ref("beta"), bad, None)


@pytest.mark.parametrize("phase", ["before-intent", "after-intent", "after-release", "after-receipt", "before-final"])
@pytest.mark.parametrize("mutation", ["unchanged", "removed", "same-lane", "foreign", "unreadable"])
def test_crash_and_lease_state_matrix(make_store, monkeypatch, record_property, phase, mutation):
    revision, _ = held(make_store)
    path = make_store / ".aegis" / "state" / "team-queue.json"
    # A rollback must preserve formatting as well as decoded scheduling facts.
    path.write_text(json.dumps(json.loads(path.read_text()), indent=2) + "\n", encoding="utf-8")
    original_bytes = path.read_bytes()
    original_publish, original_release, original_append = queue._publish, team_claims._release_lease, events.try_append
    armed, removed_by_us = [True], []

    def publication(root, state, **kwargs):
        if armed[0] and phase == "before-intent":
            raise OSError("injected before intent")
        if armed[0] and phase == "before-final" and "unclaim" not in state:
            raise OSError("injected before final")
        result = original_publish(root, state, **kwargs)
        if armed[0] and phase == "after-intent":
            raise OSError("injected after intent")
        return result

    def releasing(root, lane, oid, **kwargs):
        result = original_release(root, lane, oid, **kwargs)
        if result:
            removed_by_us.append(oid)
        if armed[0] and phase == "after-release":
            raise OSError("injected after release")
        return result

    def appending(root, kind, result, detail, **kwargs):
        outcome = original_append(root, kind, result, detail, **kwargs)
        if armed[0] and phase == "after-receipt" and result == "queue_unclaim":
            raise OSError("injected after receipt")
        return outcome

    monkeypatch.setattr(queue, "_publish", publication)
    monkeypatch.setattr(team_claims, "_release_lease", releasing)
    monkeypatch.setattr(team_claims, "events", SimpleNamespace(**{**vars(events), "try_append": appending}))
    first = unclaim(make_store, revision)
    assert first["reason"] == "unclaim_recovery_required"
    # Every blocked recovery in this matrix is an injected I/O failure. The cause
    # entry is present on the first refusal, before the lease mutation on retry.
    assert [row["reason"] for row in first["blockers"]] == [
        "unclaim_recovery_required", "queue_io_unavailable"], first
    assert set(first["blockers"][1]) == {"refused", "reason", "next_action"}, first
    assert "injected" not in json.dumps(first["blockers"])
    fault_bytes = path.read_bytes()
    pending = "unclaim" in json.loads(fault_bytes)
    assert pending is (phase != "before-intent")
    if not pending:
        assert fault_bytes == original_bytes
    armed[0] = False
    mutate_lease(make_store, mutation)
    before_retry = path.read_bytes()
    result = unclaim(make_store, revision)
    after_retry = path.read_bytes()
    rows = receipts(make_store)
    evidence = {"phase": phase, "mutation": mutation, "original_bytes": original_bytes.decode(),
        "fault_bytes": fault_bytes.decode(), "intent": json.loads(fault_bytes).get("unclaim"),
        "before_retry_bytes": before_retry.decode(), "after_retry_bytes": after_retry.decode(),
        "receipt": rows, "refusal": result.get("reason"), "our_releases": removed_by_us}
    record_property("transition_matrix", json.dumps(evidence, sort_keys=True))
    if pending and mutation in ("same-lane", "foreign", "unreadable"):
        assert result["reason"] == "unclaim_recovery_required", evidence
        assert result["exit_code"] == 1, evidence
        assert after_retry == before_retry and "unclaim" in json.loads(after_retry), evidence
        # The recovery command stays first. The second entry is only the sanitized cause.
        assert [row["reason"] for row in result["blockers"]] == [
            "unclaim_recovery_required", "unclaim_lease_refused"], evidence
        cause = result["blockers"][1]
        assert set(cause) == {"refused", "reason", "lane", "lease_oid", "next_action"}, evidence
        assert cause["lane"] == ("alpha" if mutation == "same-lane" else "beta"), evidence
        assert cause["lease_oid"] and len(cause["lease_oid"]) in (40, 64), evidence
        assert all(character in "0123456789abcdef" for character in cause["lease_oid"]), evidence
        assert "aegis team release " + cause["lane"] in cause["next_action"], evidence
        assert cause["lease_oid"] in cause["next_action"], evidence
    elif not pending and mutation in ("foreign", "unreadable"):
        assert result["reason"] == "unclaim_lease_refused" and result["exit_code"] == 1, evidence
        assert after_retry == original_bytes, evidence
        assert [row["reason"] for row in result["blockers"]] == ["unclaim_lease_refused"], evidence
    else:
        assert not result["refused"] and result["item"]["state"] == "queued", evidence
        assert "unclaim" not in json.loads(after_retry), evidence
        assert set(result["released_lease_ids"]) <= set(removed_by_us), evidence
    assert len(rows) <= 1, evidence
    for row in rows:
        assert row["detail"]["writer_stopped"] is True, evidence
        assert set(row["detail"]["released_lease_ids"]) <= set(removed_by_us), evidence


@pytest.mark.parametrize("mutation", ["same-lane", "foreign", "unreadable"])
def test_initial_lease_less_race_restores_exact_bytes(make_store, monkeypatch, mutation):
    revision, oid = held(make_store)
    team.release(make_store, "alpha", oid, caller="external")
    path = make_store / ".aegis" / "state" / "team-queue.json"
    path.write_text(json.dumps(json.loads(path.read_text()), indent=2) + "\n", encoding="utf-8")
    before, original, changed = path.read_bytes(), queue._publish, []

    def publication(root, state, **kwargs):
        original(root, state, **kwargs)
        if not changed:
            changed.append(True)
            if mutation == "same-lane":
                team.claim(root, "alpha", ["src/**"], owner="owner", now=103)
            else:
                mutate_lease(root, mutation)

    monkeypatch.setattr(queue, "_publish", publication)
    result = unclaim(make_store, revision)
    assert result["reason"] == "unclaim_lease_refused"
    assert path.read_bytes() == before and receipts(make_store) == []


def test_externally_removed_lease_is_not_attested(make_store, monkeypatch):
    revision, oid = held(make_store)
    original, changed = queue._publish, []
    path = make_store / ".aegis" / "state" / "team-queue.json"
    before = path.read_bytes()

    def publication(root, state, **kwargs):
        original(root, state, **kwargs)
        if not changed:
            changed.append(True)
            team.release(root, "alpha", oid, caller="external")

    monkeypatch.setattr(queue, "_publish", publication)
    result = unclaim(make_store, revision)
    assert result["reason"] == "unclaim_lease_refused"
    assert path.read_bytes() == before and receipts(make_store) == []


@pytest.mark.parametrize("mutation", ["same-lane", "foreign", "unreadable"])
def test_last_publication_guard_refuses_a_new_lease(make_store, monkeypatch, mutation):
    revision, _ = held(make_store)
    original = queue._publish

    def publication(root, state, **kwargs):
        if "unclaim" not in state:
            mutate_lease(root, mutation)
        return original(root, state, **kwargs)

    monkeypatch.setattr(queue, "_publish", publication)
    result = unclaim(make_store, revision)
    assert result["reason"] == "unclaim_recovery_required"
    state = json.loads((make_store / ".aegis" / "state" / "team-queue.json").read_text())
    assert "unclaim" in state and state["items"]["ONE"]["state"] == "claimed"


@pytest.mark.parametrize("offset,admitted", [(0, True), (-1, True), (1, False), (16383, False), (16384, False)])
def test_event_reservation_boundaries(make_store, monkeypatch, offset, admitted):
    revision, oid = held(make_store)
    log = events.events_path(make_store)
    # The reserved region includes both bounded events; padding is valid JSONL whitespace.
    monkeypatch.setattr(team_claims, "MAX_EVENT_BYTES", 32768)
    monkeypatch.setattr(team_claims, "EVENT_MARGIN", 16384)
    target = team_claims.MAX_EVENT_BYTES - team_claims.EVENT_MARGIN + offset
    log.write_bytes(log.read_bytes() + b" " * (target - log.stat().st_size - 1) + b"\n")
    path = make_store / ".aegis" / "state" / "team-queue.json"
    before = path.read_bytes()
    result = unclaim(make_store, revision)
    assert result["refused"] is not admitted
    if admitted:
        assert result["released_lease_ids"] == [oid]
    else:
        assert result["reason"] == "unclaim_event_unavailable"
        assert path.read_bytes() == before and team.read_leases(make_store).get("alpha").oid == oid


@pytest.mark.parametrize("failure", ["start", "timeout", "nonzero"])
def test_git_observation_failure_never_clears_holds(make_store, monkeypatch, failure):
    held(make_store)

    def failed(*args, **kwargs):
        if failure == "nonzero":
            return SimpleNamespace(returncode=128, stdout=b"", stderr=b"private-value")
        raise gitsafe.GitError("private-value " + failure)

    monkeypatch.setattr(team_claims, "gitsafe", SimpleNamespace(**{**vars(gitsafe), "run": failed}))
    result = queue.list(make_store, now=102)
    assert result["reason"] == "queue_io_unavailable" and result["exit_code"] == 1
    assert "private-value" not in json.dumps(result) and "claimable_fingerprint" not in result


def test_recovery_blockers_and_returned_hold_view(make_store, monkeypatch):
    revision, _ = held(make_store)
    path = make_store / ".aegis" / "state" / "team-queue.json"
    state = json.loads(path.read_text())
    state["items"]["ONE"]["item"]["hold_until"] = [{"kind": "lease_free", "paths": ["docs/**"]}]
    path.write_text(json.dumps(state), encoding="utf-8")
    original = team_claims._release_lease

    def failed(*args, **kwargs):
        raise OSError("private-value")

    monkeypatch.setattr(team_claims, "_release_lease", failed)
    first = unclaim(make_store, revision, reason="Waiting for review")
    monkeypatch.setattr(team_claims, "_release_lease", original)
    assert [row["reason"] for row in first["blockers"]] == [
        "unclaim_recovery_required", "queue_io_unavailable"]
    assert set(first["blockers"][1]) == {"refused", "reason", "next_action"}
    assert "private-value" not in json.dumps(first)
    for result in (first, queue.list(make_store, now=102), queue.audit(make_store, now=102)):
        blocker = result["blockers"][0]
        assert (blocker["item_id"], blocker["lane"], blocker["revision"], blocker["caller"]) == (
            "ONE", "alpha", revision, "owner")
        assert revision in blocker["next_action"] and "--writer-stopped" in blocker["next_action"]
        assert blocker["reason_text"] == "Waiting for review"
    for result in (queue.list(make_store, now=102), queue.audit(make_store, now=102)):
        assert [row["reason"] for row in result["blockers"]] == ["unclaim_recovery_required"]
    result = unclaim(make_store, revision)
    assert not result["refused"] and result["item"]["conditions_met"] is False
    assert result["item"]["blockers"][0]["reason"] == "lease_free"


def test_initial_receipt_log_is_read_once(make_store, monkeypatch):
    revision, _ = held(make_store)
    opened = []
    original = storage.confined_file

    def counted(*args, **kwargs):
        opened.append(args)
        return original(*args, **kwargs)

    monkeypatch.setattr(team_claims, "storage", SimpleNamespace(**{**vars(storage), "confined_file": counted}))
    assert not unclaim(make_store, revision)["refused"]
    assert len(opened) == 1


def test_recovery_reads_bounded_event_slack(make_store, monkeypatch):
    revision, _ = held(make_store)
    monkeypatch.setattr(team_claims, "MAX_EVENT_BYTES", 32768)
    monkeypatch.setattr(team_claims, "EVENT_MARGIN", 16384)
    original_append, original_publish = events.try_append, queue._publish

    def appended_after_other_events(root, kind, result, detail, **kwargs):
        if result == "queue_unclaim":
            log = events.events_path(root)
            padding = team_claims.MAX_EVENT_BYTES + 100 - log.stat().st_size
            log.write_bytes(log.read_bytes() + b" " * (padding - 1) + b"\n")
        return original_append(root, kind, result, detail, **kwargs)

    def publication(root, state, **kwargs):
        if "unclaim" not in state:
            raise OSError("injected before final")
        return original_publish(root, state, **kwargs)

    monkeypatch.setattr(team_claims, "events", SimpleNamespace(**{**vars(events), "try_append": appended_after_other_events}))
    monkeypatch.setattr(queue, "_publish", publication)
    assert unclaim(make_store, revision)["reason"] == "unclaim_recovery_required"
    monkeypatch.setattr(team_claims, "events", events)
    monkeypatch.setattr(queue, "_publish", original_publish)
    assert events.events_path(make_store).stat().st_size > team_claims.MAX_EVENT_BYTES
    assert not unclaim(make_store, revision)["refused"] and len(receipts(make_store)) == 1


def test_retry_release_cas_refusal_retains_intent(make_store, monkeypatch):
    revision, _ = held(make_store)
    original = team_claims._release_lease

    def unavailable(*args, **kwargs):
        raise OSError("injected before release")

    monkeypatch.setattr(team_claims, "_release_lease", unavailable)
    assert unclaim(make_store, revision)["reason"] == "unclaim_recovery_required"
    path = make_store / ".aegis" / "state" / "team-queue.json"
    before = path.read_bytes()

    def moved(root, lane, oid, **kwargs):
        team.renew(root, lane, oid, now=103)
        return original(root, lane, oid, **kwargs)

    monkeypatch.setattr(team_claims, "_release_lease", moved)
    result = unclaim(make_store, revision)
    assert result["reason"] == "unclaim_recovery_required"
    assert path.read_bytes() == before and "unclaim" in json.loads(before)


def test_maximum_reason_keeps_a_complete_retry_command(make_store, monkeypatch):
    revision, _ = held(make_store)
    reason = "A" * queue.MAX_TEXT
    original = team_claims._release_lease

    def failed(*args, **kwargs):
        raise OSError("injected before release")

    monkeypatch.setattr(team_claims, "_release_lease", failed)
    result = unclaim(make_store, revision, reason=reason)
    blocker = result["blockers"][0]
    action = blocker["next_action"]
    assert action.startswith("Retry as the recorded caller: ")
    assert action.index("--writer-stopped") < action.index("--workspace")
    assert str(make_store) in action and len(action) <= queue.MAX_TEXT
    assert action == queue._shown(action) and "\n" not in action
    assert blocker["reason_text"] == reason
    monkeypatch.setattr(team_claims, "_release_lease", original)
    assert not unclaim(make_store, revision)["refused"]


def test_initial_io_refusal_before_release_restores_exact_bytes(make_store, monkeypatch):
    revision, oid = held(make_store)
    path = make_store / ".aegis" / "state" / "team-queue.json"
    path.write_text(json.dumps(json.loads(path.read_text()), indent=2) + "\n", encoding="utf-8")
    before, original, reads = path.read_bytes(), team.read_leases, []

    def failed(root):
        reads.append(True)
        if len(reads) > 1:
            raise gitsafe.GitError("private-value")
        return original(root)

    monkeypatch.setattr(team_claims, "team", SimpleNamespace(**{**vars(team), "read_leases": failed}))
    result = unclaim(make_store, revision)
    assert result["reason"] == "queue_io_unavailable" and "private-value" not in json.dumps(result)
    assert path.read_bytes() == before and team.read_leases(make_store).get("alpha").oid == oid


def test_external_delete_inside_cas_is_never_attested(make_store, monkeypatch):
    revision, oid = held(make_store)
    original, removed = gitsafe.update_ref, []

    def external_delete(root, ref, new, old, **kwargs):
        if new is None and ref == team.lane_ref("alpha") and not removed:
            original(root, ref, None, old, single_attempt=True)
            removed.append(old)
        return original(root, ref, new, old, **kwargs)

    proxy = SimpleNamespace(**{**vars(gitsafe), "update_ref": external_delete})
    monkeypatch.setattr(team, "gitsafe", proxy)
    monkeypatch.setattr(team_claims, "gitsafe", proxy)
    result = unclaim(make_store, revision)
    assert oid not in result.get("released_lease_ids", [])
    assert all(oid not in row["detail"]["released_lease_ids"] for row in receipts(make_store))
    monkeypatch.setattr(team, "gitsafe", gitsafe)
    monkeypatch.setattr(team_claims, "gitsafe", gitsafe)
    if result["refused"]:
        assert result["reason"] == "unclaim_recovery_required"
        result = unclaim(make_store, revision)
    assert not result["refused"] and result["released_lease_ids"] == []


def pad_queue(root, target):
    path = root / ".aegis" / "state" / "team-queue.json"
    state = json.loads(path.read_bytes())
    state["items"]["PAD"] = {"item": {"id": "PAD", "title": "Retained work", "paths": ["pad/**"],
        "capabilities": [], "invariants": []}, "state": "done", "revision": "1" * 64,
        "lane": None, "expires_at": None}
    state["items"]["ONE"]["item"]["invariants"] = []
    remaining = target - len(json.dumps(state, separators=(",", ":")).encode("ascii"))
    for identifier in ("ONE", "PAD"):
        values = state["items"][identifier]["item"]["invariants"]
        while remaining and len(values) < queue.MAX_FIELDS:
            length = min(queue.MAX_TEXT, remaining - 2 - bool(values))
            assert length >= 0
            values.append("x" * length)
            remaining -= length + 2 + (len(values) > 1)
    assert remaining == 0
    raw = json.dumps(state, separators=(",", ":")).encode("ascii")
    assert len(raw) == target <= queue.MAX_BYTES
    path.write_bytes(raw)
    assert not queue.list(root, now=102)["refused"]
    return path, raw


@pytest.mark.parametrize("phase", ["intent", "released-ids"])
def test_unclaim_queue_size_failure_preserves_phase_and_compact_guidance(make_store, phase):
    revision, oid = held(make_store)
    intent = {"id": "ONE", "revision": revision, "lane": "alpha", "caller": "owner", "reason": "",
        "lease_oid": oid, "to_revision": "0" * 64, "writer_stopped": True, "released_lease_ids": []}
    overhead = len(',"unclaim":' + json.dumps(intent, separators=(",", ":")))
    target = queue.MAX_BYTES - 1 - (overhead if phase == "released-ids" else 0)
    path, before = pad_queue(make_store, target)
    result = unclaim(make_store, revision)
    assert result["refused"] and result["exit_code"] == 1
    assert result["reason"] == ("queue_size_limit" if phase == "intent" else "unclaim_recovery_required")
    assert "aegis team queue compact" in json.dumps(result)
    if phase == "released-ids":
        assert [row["reason"] for row in result["blockers"]] == [
            "unclaim_recovery_required", "queue_size_limit"]
        assert set(result["blockers"][1]) == {"refused", "reason", "next_action"}
    assert receipts(make_store) == []
    if phase == "intent":
        assert path.read_bytes() == before
        assert team.read_leases(make_store).get("alpha").oid == oid
    else:
        pending = json.loads(path.read_bytes())["unclaim"]
        assert pending["released_lease_ids"] == [] and pending["lease_oid"] == oid
        assert team.read_leases(make_store).get("alpha") is None
        recovered = unclaim(make_store, revision)
        assert not recovered["refused"] and recovered["item"]["state"] == "queued"
        assert recovered["released_lease_ids"] == []
        assert len(receipts(make_store)) == 1 and "unclaim" not in json.loads(path.read_bytes())


@pytest.mark.timing
@pytest.mark.parametrize("case", ["holds", "foreign-lease"])
def test_large_fingerprint_observation_has_linear_evaluation_budget(make_store, monkeypatch, record_property, case):
    count, lane_count, holds = 128, 4000, 64 if case == "holds" else 0
    config = {"v": 1, "lanes": {"l%04d" % index: [] for index in range(lane_count)}}
    config_raw = json.dumps(config, separators=(",", ":")).encode("ascii")
    assert len(config_raw) < 65536
    (make_store / ".aegis" / "team.json").write_bytes(config_raw)
    state = {"version": 1, "items": {}, "milestones": [], "completed": {}}
    for index in range(count):
        identifier = "I%03d" % index
        state["items"][identifier] = {"item": {"id": identifier, "title": "Work", "paths": ["src/**"],
            "capabilities": [], "hold_until": [{"kind": "lease_free", "paths": ["src/**"]}] * holds},
            "state": "queued", "revision": "%064x" % index, "lane": None, "expires_at": None}
    path = make_store / ".aegis" / "state" / "team-queue.json"
    path.parent.mkdir()
    raw = json.dumps(state, separators=(",", ":")).encode("ascii")
    assert len(raw) <= queue.MAX_BYTES
    path.write_bytes(raw)
    lease = team.claim(make_store, "l3999", ["src/**"], owner="owner", now=100)
    counts = {"items": 0, "holds": 0, "overlaps": 0, "live_checks": 0,
              "foreign_lease": 0, "capacity": 0}
    original_blockers, original_live, paths = queue._blockers, queue._live, queue.team_paths
    original_foreign, original_capacity = queue._foreign_lease, queue._capacity

    def blockers(item, *args, **kwargs):
        counts["items"] += 1
        counts["holds"] += len(item.get("hold_until", []))
        assert counts["items"] <= count, counts
        return original_blockers(item, *args, **kwargs)

    def overlap(*args):
        counts["overlaps"] += 1
        assert counts["overlaps"] <= count * (holds + 2), counts
        return paths.overlap(*args)

    def live(*args):
        counts["live_checks"] += 1
        assert counts["live_checks"] <= 4 * (count * holds + count * lane_count), counts
        return original_live(*args)

    def foreign(*args):
        counts["foreign_lease"] += 1
        return original_foreign(*args)

    def capacity(*args):
        counts["capacity"] += 1
        return original_capacity(*args)

    monkeypatch.setattr(queue, "_blockers", blockers)
    monkeypatch.setattr(queue, "_live", live)
    monkeypatch.setattr(queue, "_foreign_lease", foreign)
    monkeypatch.setattr(queue, "_capacity", capacity)
    monkeypatch.setattr(queue, "team_paths", SimpleNamespace(**{**vars(paths), "overlap": overlap}))
    started = time.monotonic()
    result = queue.list(make_store, now=102)
    elapsed = time.monotonic() - started
    assert not result["refused"] and len(result["items"]) == count
    assert counts["holds"] == count * holds
    assert elapsed < 30, (elapsed, counts)
    record_property("observation_budget", json.dumps({**counts, "seconds": elapsed,
        "config_bytes": len(config_raw), "queue_bytes": len(raw), "lanes": lane_count, "items": count}))
    assert counts["foreign_lease"] == 0, counts
    assert counts["capacity"] <= lane_count, counts
    monkeypatch.setattr(queue, "_blockers", original_blockers)
    monkeypatch.setattr(queue, "_live", original_live)
    monkeypatch.setattr(queue, "team_paths", paths)
    monkeypatch.setattr(queue, "_foreign_lease", original_foreign)
    monkeypatch.setattr(queue, "_capacity", original_capacity)
    revision = result["items"][0]["revision"]
    claimed = queue.claim(make_store, "I000", expect=revision, lane="l3999", now=102)
    assert claimed["refused"] is (case == "holds")
    assert team.read_leases(make_store).get("l3999").oid == lease.oid


# Captured through queue.list before the round-three eligibility refactor.
ROUND_TWO_FINGERPRINTS = {
    "capacity": "162258c7ce5dec555aadf8aaa186679e6cb9c5baac7373d50668d67d274c63c6",
    "completed": "8e7ebcd88a45c3c3ab060b099b5e9cf52f99b53bceddde0b5c1927f37b3592e3",
    "dependency": "909972b8569e17b9200e90358cec22f9daef4fc295b642380e5e22ae9d4561db",
    "expired": "79cf67effd83b5ae8597ebe36054f3c72d9bdee0b22ad2ef2d63e6d7fc27f09c",
    "foreign-lease": "162258c7ce5dec555aadf8aaa186679e6cb9c5baac7373d50668d67d274c63c6",
    "invalid-profile": "b6630774f47e0b674f8eb26fe4a5182bdad6adfbc63696c29a0a2b44c59a9d75",
    "judgment": "35d1c4885b682e0066582224aef744ed8584e34b4351f0261ab1166b10d37cb8",
    "live": "9b7b500941401d0b9fa63401d40e4b27fed98ca25c75ecc2c5e770ba7eb53487",
    "milestone": "abfe5e4310590811dece721310638e8fa43eff91ece1520165eeab16872f530c",
    "no-lanes": "598998c636df61cba70010c24d5c326496a8154f69d12203e53645cf2c91cf0d",
    "own-lease": "370934775538b01d7cfba28903c45685c0baf710e5af4997fd8c590151cbfb28",
    "queued": "512658d25aa593fd9f0dbcbdfb26a4d5e5ea9f3e7c44a6986ecc3a501bac5aa6",
    "unreadable": "1b4401d55ed4f8f8f109c3c8bfbc549765ac9d3a8f998b84cd7e2c17e43e24c4",
}


@pytest.mark.parametrize("case", ROUND_TWO_FINGERPRINTS)
def test_round_two_fingerprint_golden(make_store, monkeypatch, record_property, case):
    row = {"item": {"id": "ONE", "title": "Work", "paths": ["src/**"], "capabilities": []},
        "state": "queued", "revision": "1" * 64, "lane": None, "expires_at": None}
    state = {"version": 1, "items": {"ONE": row}, "milestones": [], "completed": {}}
    found = team.LeaseSet()
    if case == "judgment":
        row["item"]["hold"] = "Review"
    elif case == "dependency":
        row["item"]["after"] = ["PRE"]
    elif case == "milestone":
        row["item"]["hold_until"] = [{"kind": "milestone", "name": "landed"}]
    elif case in ("live", "expired"):
        row.update(state="claimed", lane="alpha", expires_at=103 if case == "live" else 102)
    elif case in ("own-lease", "foreign-lease", "capacity"):
        lane = "alpha" if case == "own-lease" else "foreign"
        paths = ("docs/**",) if case == "capacity" else ("src/**",)
        found = team.LeaseSet((team.Lease(lane, "implementer", "owner", "0" * 16, 1,
                                        None, paths, 100, 3600, "a" * 40),), ())
    elif case == "unreadable":
        found = team.LeaseSet((), (team.Unreadable("foreign", team.lane_ref("foreign"), "b" * 40, "invalid"),))
    elif case == "invalid-profile":
        profile = make_store / ".aegis" / "team" / "profile.json"
        profile.parent.mkdir()
        profile.write_text("{}", encoding="utf-8")
    elif case == "no-lanes":
        (make_store / ".aegis" / "team.json").write_text('{"v":1,"lanes":{}}', encoding="utf-8")
    elif case == "completed":
        state["completed"]["PRE"] = True
        row["item"]["after"] = ["PRE"]
    path = make_store / ".aegis" / "state" / "team-queue.json"
    path.parent.mkdir()
    path.write_text(json.dumps(state, separators=(",", ":")), encoding="utf-8")
    monkeypatch.setattr(team_claims, "observe_leases", lambda root: (found, True))
    result = queue.list(make_store, now=102)
    assert not result["refused"], result
    record_property("round_two_golden", json.dumps({case: result["claimable_fingerprint"]}))
    assert result["claimable_fingerprint"] == ROUND_TWO_FINGERPRINTS[case]


# Public full-list response hashes captured at d896c4db before product edits.
LANE_ELIGIBILITY_GOLDENS = {
    "empty": "e1395b2bd419e1e2aeb537041a844ef9266fa7de16bf874b8641f2734ec26787",
    "cover-alpha": "2f43411ae899098a532d6949ecc3d62e50589cece06a7f7a08477bc0bdefb380",
    "cover-beta": "ece667d317c79e2fd0bd18df6f0f185bf04501f96977c05e31a4c41dd495f344",
    "cover-two": "cca91a8d827952b90274355a4592a700b64e0963a11d92f395cf25e85dab14e8",
    "cover-unconfigured": "03a3a521a094a759def2001e0350d256f7689e8f7b7d80b627f1076b9d28b155",
    "busy-cover": "186c01a4b25b2d4cdd4932eda7d06d4738bfb73b58514219458d20cceab90659",
    "busy-other": "9063f30b3d7f83dc50fe90212f0f4fe37b4ae469d971557fa4ce632eb7fd7f24",
    "busy-all": "27783ed7d5fbe427bfd0b1cdd3026a534ea382b5a913f4c045bef2e54c4b724a",
    "capacity-cover": "11b4dae0dfeba1f5ced56bf649156215ad9fa690381a4ed23a0c1508a02baab9",
    "capacity-empty": "f4e907d8122600c044fdc039a762e70d637f6b178ddc1246c7124dcb3393a7dd",
    "over-capacity": "e840265df73173094d71b60c38dd2950a15d50b90567eefc7a79bc02ef967915",
    "invalid-profile": "b3797bbdb6aa1642bc30bef6685feb0f71545f4ebf742eeb6cec8c30b4af41a9",
    "unchecked": "ca32255d9472dee8c9956f9601ee77925a6897d943dfa64c7b2d92fd4fcb710a",
    "unreadable": "812da6d72e931a910078d9aa72da9be24b7156afc78fbdd0bada968f226df834",
    "done": "8107aa3525fd39fe96e9c01037ebaabe64f33c065397d9c813f56bc02294c197",
    "live": "099dd4b9c8acb5e4f2b5deea46d752f631ba4bc56c65c5875622dd518a20372e",
    "expired": "c5d8679843f9c195682bd1b3de8de843efa19b362fa41b32367157fac0fa9420",
    "no-lanes": "5c0899720345c4107f16946d81b9ef32d6895058a9b80b307e57c02d618e5790",
}


@pytest.mark.parametrize("case,claimable", [
    ("empty", True), ("cover-alpha", True), ("cover-beta", True),
    ("cover-two", False), ("cover-unconfigured", False),
    ("busy-cover", False), ("busy-other", True), ("busy-all", False),
    ("capacity-cover", True), ("capacity-empty", False), ("over-capacity", False),
    ("invalid-profile", False), ("unchecked", False), ("unreadable", False),
    ("done", False), ("live", False), ("expired", True), ("no-lanes", False),
])
def test_list_lane_eligibility_matrix(make_store, monkeypatch, record_property, case, claimable):
    row = {"item": {"id": "ONE", "title": "Work", "paths": ["src/**"], "capabilities": []},
        "state": "queued", "revision": "1" * 64, "lane": None, "expires_at": None}
    state = {"version": 1, "items": {"ONE": row}, "milestones": [], "completed": {}}
    lanes = {"alpha": ["src/**"], "beta": ["docs/**"]}
    lease_specs = {
        "cover-alpha": [("alpha", "src/**")], "cover-beta": [("beta", "src/**")],
        "cover-two": [("alpha", "src/**"), ("beta", "src/**")],
        "cover-unconfigured": [("foreign", "src/**")],
        "busy-cover": [("alpha", "src/**")], "busy-other": [("alpha", "src/**")],
        "capacity-cover": [("alpha", "src/**")], "capacity-empty": [("foreign", "docs/**")],
        "over-capacity": [("alpha", "src/**"), ("beta", "docs/**")],
    }
    leases = tuple(team.Lease(lane, "implementer", "owner", "0" * 16, 1, None,
                             (scope,), 100, 3600, str(index + 1) * 40)
                   for index, (lane, scope) in enumerate(lease_specs.get(case, [])))
    unreadable = ((team.Unreadable("foreign", team.lane_ref("foreign"), "b" * 40, "invalid"),)
                  if case == "unreadable" else ())
    found, checked = team.LeaseSet(leases, unreadable), case != "unchecked"
    if case in ("busy-cover", "busy-other", "busy-all"):
        busy_lanes = ("alpha", "beta") if case == "busy-all" else (
            "beta" if case == "busy-other" else "alpha",)
        for lane in busy_lanes:
            state["items"][lane] = {"item": {"id": lane, "title": "Busy", "paths": ["busy/**"],
                "capabilities": []}, "state": "claimed", "revision": "2" * 64,
                "lane": lane, "expires_at": 200}
    if case == "done":
        row["state"] = "done"
    elif case in ("live", "expired"):
        row.update(state="claimed", lane="alpha", expires_at=103 if case == "live" else 102)
    elif case == "no-lanes":
        lanes = {}
        (make_store / ".aegis" / "team.json").write_text('{"v":1,"lanes":{}}', encoding="utf-8")
    limit = 1 if case.startswith("capacity-") or case == "over-capacity" else 2
    policy = {"valid": True, "writers_max": limit} if case != "invalid-profile" else {"valid": False}
    profile = make_store / ".aegis" / "team" / "profile.json"
    profile.parent.mkdir()
    profile.write_text(json.dumps({"version": 1, "run_config": {"limits": {"writers_max": limit}}})
                       if policy["valid"] else "{}", encoding="utf-8")
    path = make_store / ".aegis" / "state" / "team-queue.json"
    path.parent.mkdir()
    path.write_text(json.dumps(state, separators=(",", ":")), encoding="utf-8")
    before = path.read_bytes()
    monkeypatch.setattr(team_claims, "observe_leases", lambda root: (found, checked))
    expected = team_claims.fingerprint(state, found, 102,
        [["ONE", row["revision"]]] if claimable else [], lanes or None, policy, checked)
    for _ in range(2):
        result = queue.list(make_store, now=102, include_done=True)
        assert not result["refused"], result
        assert result["claimable_fingerprint"] == expected
        assert queue.list(make_store, now=102, view="fingerprint")["claimable_fingerprint"] == expected
        assert path.read_bytes() == before
    # Exclude the release version so a version bump does not invalidate the fixture.
    payload = {key: value for key, value in result.items() if key != "aegis_version"}
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii")).hexdigest()
    record_property("lane_eligibility_golden", json.dumps({case: digest}))
    assert digest == LANE_ELIGIBILITY_GOLDENS[case]


@pytest.mark.parametrize("view", ["full", "fingerprint"])
def test_list_lane_eligibility_unsupported_platform(tmp_path, monkeypatch, view):
    monkeypatch.setattr(queue, "descriptor_supported", lambda: False)
    result = queue.list(tmp_path, now=102, view=view)
    assert result["refused"] and result["reason"] == "unsupported_platform"
    assert result["exit_code"] == 1


def test_list_lane_eligibility_uses_one_lease_snapshot_and_refreshes(make_store, monkeypatch):
    added = queue.add(make_store, {"id": "ONE", "title": "Work", "paths": ["src/**"],
                                 "capabilities": []}, now=100)
    assert not added["refused"], added
    before = queue.list(make_store, now=102)
    original, published = queue._capacity, []

    def publish_during_observation(*args):
        if not published:
            published.append(team.claim(make_store, "foreign", ["src/**"], owner="owner", now=100))
        return original(*args)

    monkeypatch.setattr(queue, "_capacity", publish_during_observation)
    assert queue.list(make_store, now=102) == before
    assert len(published) == 1
    after = queue.list(make_store, now=102)
    assert not after["refused"], after
    assert after["claimable_fingerprint"] != before["claimable_fingerprint"]
    assert queue.list(make_store, now=102) == after
    team.release(make_store, "foreign", published[0].oid, caller="owner")
    assert queue.list(make_store, now=102) == before


def plant_pending(root, monkeypatch):
    """Publish one pending unclaim, then fail before the lease release."""
    revision, oid = held(root)
    original = queue._publish

    def fail_after(store, state, **kwargs):
        original(store, state, **kwargs)
        if "unclaim" in state:
            raise OSError("injected")

    monkeypatch.setattr(queue, "_publish", fail_after)
    failed = unclaim(root, revision)
    monkeypatch.setattr(queue, "_publish", original)
    assert failed["reason"] == "unclaim_recovery_required", failed
    path = root / ".aegis" / "state" / "team-queue.json"
    assert "unclaim" in json.loads(path.read_bytes())
    return revision, oid, path


def cause_of(result):
    assert result["reason"] == "unclaim_recovery_required" and result["exit_code"] == 1, result
    assert result["blockers"][0]["reason"] == "unclaim_recovery_required"
    return result["blockers"][1]


def test_initial_event_refusal_restores_queue_bytes(make_store):
    revision, oid = held(make_store)
    log = events.events_path(make_store)
    original_log = log.read_bytes()
    log.write_bytes(original_log + b'{"token":"private-value"\n')
    path = make_store / ".aegis" / "state" / "team-queue.json"
    before = path.read_bytes()
    result = unclaim(make_store, revision)
    assert result["reason"] == "unclaim_event_unavailable" and result["exit_code"] == 1
    assert "private-value" not in json.dumps(result)
    assert path.read_bytes() == before and "unclaim" not in json.loads(before)
    assert team.read_leases(make_store).get("alpha").oid == oid
    log.write_bytes(original_log)
    assert not unclaim(make_store, revision)["refused"]


def test_initial_duplicate_rows_are_not_a_receipt_conflict(make_store):
    revision, _ = held(make_store)
    log = events.events_path(make_store)
    row = (b'{"event":"lease_claimed","result":"queue_unclaim","detail":{"unclaim_id":"'
           + b"ab" * 32 + b'"}}\n')
    log.write_bytes(log.read_bytes() + row + row)
    assert not unclaim(make_store, revision)["refused"]


@pytest.mark.parametrize("blocker", ["foreign", "unreadable", "missing-newline", "torn-row",
    "malformed", "duplicate"])
def test_recovery_cause_names_the_blocker_and_retries(make_store, monkeypatch, blocker):
    revision, oid, path = plant_pending(make_store, monkeypatch)
    before = path.read_bytes()
    log = events.events_path(make_store)
    original_log = log.read_bytes()
    pending = json.loads(before)["unclaim"]
    if blocker == "foreign":
        # A second src/** lease cannot be claimed while alpha's live lease overlaps it.
        team.release(make_store, "alpha", oid, caller="external")
        team.claim(make_store, "beta", ["src/**"], owner="someone-else", now=100)
    elif blocker == "unreadable":
        bad = gitsafe.write_blob(make_store, b'{"token":"private-value"}')
        gitsafe.update_ref(make_store, team.lane_ref("beta"), bad, None)
    elif blocker == "missing-newline":
        log.write_bytes(original_log + b'{"token":"private-value"')
    elif blocker == "torn-row":
        log.write_bytes(original_log + b'{"token":"private-value"\n')
    elif blocker == "malformed":
        log.write_bytes(original_log + b'"private-value"\n')
    else:
        receipt = (json.dumps({"event": "lease_claimed", "result": "queue_unclaim", "detail": {
            "unclaim_id": pending["to_revision"], "note": "private-value"}},
            separators=(",", ":")).encode("ascii") + b"\n")
        log.write_bytes(original_log + receipt + receipt)
    for _ in range(2):
        result = unclaim(make_store, revision)
        cause = cause_of(result)
        assert path.read_bytes() == before
        assert "private-value" not in json.dumps(result)
        assert "\n" not in json.dumps(cause)
        if blocker in ("foreign", "unreadable"):
            assert cause["reason"] == "unclaim_lease_refused"
            assert cause["lane"] == "beta" and cause["lease_oid"]
            release = cause["next_action"].split(": ", 1)[1]
            assert release.startswith("aegis team release beta --expect " + cause["lease_oid"] + " --workspace ")
            assert str(make_store) in release
        else:
            assert cause["reason"] == "unclaim_event_unavailable"
            assert set(cause) == {"refused", "reason", "next_action"}
    if blocker == "foreign":
        foreign = team.read_leases(make_store).get("beta")
        team.release(make_store, "beta", foreign.oid, caller="someone-else")
    elif blocker == "unreadable":
        team.release(make_store, "beta", bad, caller="owner")
    else:
        log.write_bytes(original_log)
    recovered = unclaim(make_store, revision)
    assert not recovered["refused"], recovered
    assert recovered["item"]["state"] == "queued"
    assert team.read_leases(make_store).get("alpha") is None
    if blocker == "foreign":
        assert recovered["released_lease_ids"] == []
    else:
        assert oid in recovered["released_lease_ids"]


def test_recovery_cause_omits_unsanitized_lease_facts(make_store, monkeypatch):
    revision, _, path = plant_pending(make_store, monkeypatch)
    before = path.read_bytes()

    def hostile(root):
        return SimpleNamespace(leases=(), unreadable=(SimpleNamespace(
            lane="beta\nprivate-value", oid="not-an-oid/private-value"),))

    monkeypatch.setattr(team_claims, "team", SimpleNamespace(**{**vars(team), "read_leases": hostile}))
    result = unclaim(make_store, revision)
    cause = cause_of(result)
    assert cause["reason"] == "unclaim_lease_refused"
    assert "lane" not in cause and "lease_oid" not in cause
    listed = cause["next_action"]
    assert listed.startswith("aegis team list --json --workspace ")
    assert listed.endswith("; ask the coordinator to repair the unreadable ref")
    assert str(make_store) in listed and "private-value" not in listed
    assert "private-value" not in json.dumps(result)
    assert "beta private-value" not in json.dumps(result)
    assert path.read_bytes() == before


def test_recovery_lease_refusal_omits_exception_text(make_store, monkeypatch):
    revision, _, path = plant_pending(make_store, monkeypatch)
    before = path.read_bytes()
    current = "ab" * 20

    def leaked(*args, **kwargs):
        raise team.LeaseRefused("leak private-value /tmp/secret", "stale", "alpha", current=current)

    monkeypatch.setattr(team_claims, "_release_lease", leaked)
    result = unclaim(make_store, revision)
    cause = cause_of(result)
    assert cause["reason"] == "unclaim_lease_refused"
    assert cause["lane"] == "alpha" and cause["lease_oid"] == current
    assert "private-value" not in json.dumps(result) and "/tmp/secret" not in json.dumps(result)
    assert path.read_bytes() == before


def test_concurrent_recovery_retries_keep_one_lease_cause(make_store, monkeypatch):
    revision, oid, path = plant_pending(make_store, monkeypatch)
    before = path.read_bytes()
    team.release(make_store, "alpha", oid, caller="external")
    team.claim(make_store, "beta", ["src/**"], owner="someone-else", now=100)
    with ProcessPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(race_unclaim, [(make_store, revision)] * 2, timeout=30))
    assert path.read_bytes() == before
    assert [result["reason"] for result in results] == ["unclaim_recovery_required"] * 2
    for result in results:
        cause = cause_of(result)
        assert cause["reason"] == "unclaim_lease_refused" and cause["lane"] == "beta"
        assert "private-value" not in json.dumps(result)
    foreign = team.read_leases(make_store).get("beta")
    team.release(make_store, "beta", foreign.oid, caller="someone-else")
    recovered = unclaim(make_store, revision)
    assert not recovered["refused"], recovered
    assert recovered["released_lease_ids"] == []


def _receipt_row(token, **detail):
    body = {"unclaim_id": token, "writer_stopped": True, "released_lease_ids": []}
    body.update(detail)
    return json.dumps({"event": "lease_claimed", "result": "queue_unclaim", "detail": body},
                      separators=(",", ":")).encode("ascii")


def _parity_log(case):
    token = "ab" * 32
    row = _receipt_row(token)
    other = b'{"event":"lease_claimed","result":"released","detail":{}}'
    if case == "lf":
        raw = other + b"\n" + row + b"\n"
    elif case == "crlf":
        raw = other + b"\r\n" + row + b"\r\n"
    elif case == "blank-rows":
        raw = b"\n \n\t\n\v\n\f\n\r\n" + row + b"\n\n"
    elif case == "missing-trailing-newline":
        raw = row
    elif case == "torn-last-row":
        raw = row + b"\n" + b'{"event":"private-value"\n'
    elif case == "duplicate-receipt":
        raw = (row + b"\n") * 2
    elif case == "cr-terminated":
        raw = other + b"\r" + row + b"\n"
    elif case in ("boundary-exact", "boundary-over"):
        boundary = team_claims.MAX_EVENT_BYTES - team_claims.EVENT_MARGIN
        line = row + b"\n"
        extra = 0 if case == "boundary-exact" else 1
        raw = line + (b" " * (boundary + extra - len(line) - 1)) + b"\n"
        assert len(raw) == boundary + extra and raw.endswith(b"\n")
    else:
        raise AssertionError(case)
    return token, raw


def _oracle_scan(raw, correlation, decode):
    if correlation is None and len(raw) > team_claims.MAX_EVENT_BYTES - team_claims.EVENT_MARGIN:
        raise team_claims.ClaimRefusal("unclaim_event_unavailable")
    if raw and not raw.endswith(b"\n"):
        raise team_claims.ClaimRefusal("unclaim_event_unavailable")
    receipt = None
    for line in raw.splitlines():
        if not line.strip():
            continue
        try:
            row = decode(line, "invalid_queue_state")
        except ValueError:
            raise team_claims.ClaimRefusal("unclaim_event_unavailable") from None
        if type(row) is not dict:
            raise team_claims.ClaimRefusal("unclaim_event_unavailable")
        detail = row.get("detail")
        if (correlation is not None and row.get("event") == "lease_claimed" and
                row.get("result") == "queue_unclaim" and type(detail) is dict and
                detail.get("unclaim_id") == correlation):
            if receipt is not None:
                raise team_claims.ClaimRefusal("unclaim_event_unavailable")
            receipt = detail
    return receipt


def _scan_outcome(raw, correlation, decode):
    try:
        return ("ok", team_claims._scan_event_log(raw, correlation, decode))
    except team_claims.ClaimRefusal as error:
        return ("refuse", error.reason)


def _oracle_outcome(raw, correlation, decode):
    try:
        return ("ok", _oracle_scan(raw, correlation, decode))
    except team_claims.ClaimRefusal as error:
        return ("refuse", error.reason)


@pytest.mark.parametrize("case", ["lf", "crlf", "blank-rows", "missing-trailing-newline", "torn-last-row",
    "duplicate-receipt", "boundary-exact", "boundary-over", "cr-terminated"])
def test_event_log_decoder_matches_splitlines_parity(case):
    token, raw = _parity_log(case)
    expected_lines = [line for line in raw.splitlines() if line.strip()]
    assert list(team_claims._iter_event_rows(raw)) == expected_lines
    correlation = None if case == "boundary-over" else token
    assert _scan_outcome(raw, correlation, queue._json) == _oracle_outcome(raw, correlation, queue._json)
    if case == "boundary-exact":
        assert _scan_outcome(raw, None, queue._json) == ("ok", None)
        assert _oracle_outcome(raw, None, queue._json) == ("ok", None)
    if case == "boundary-over":
        seen = []

        def decode(line, reason):
            seen.append(line)
            return queue._json(line, reason)

        assert _scan_outcome(raw, None, decode) == ("refuse", "unclaim_event_unavailable")
        assert seen == []
    if case in ("missing-trailing-newline", "torn-last-row", "duplicate-receipt"):
        assert _scan_outcome(raw, token, queue._json)[0] == "refuse"
        rendered = json.dumps(_scan_outcome(raw, token, queue._json))
        assert "private-value" not in rendered


def test_overlong_event_row_is_refused_before_decode():
    raw = b"{" + (b"x" * team_claims._EVENT_ROW_BYTES) + b"}\n"
    assert team_claims._EVENT_ROW_BYTES == queue.MAX_BYTES
    seen = []

    def decode(line, reason):
        seen.append(len(line))
        raise AssertionError("decoded an overlong row")

    with pytest.raises(team_claims.ClaimRefusal) as caught:
        team_claims._scan_event_log(raw, "ab" * 32, decode)
    assert caught.value.reason == "unclaim_event_unavailable" and caught.value.blockers is None
    assert seen == []
    assert "x" * 32 not in str(caught.value)


def test_receipt_scan_memory_is_one_row():
    import tracemalloc
    token = "cd" * 32
    rows = [b'{"event":"lease_denied","result":"refused","detail":{"n":%d}}\n' % index
            for index in range(6000)]
    rows.append(_receipt_row(token) + b"\n")
    raw = b"".join(rows)
    assert len(raw) > 256 * 1024
    team_claims._scan_event_log(_receipt_row(token) + b"\n", token, queue._json)
    tracemalloc.start()
    found = team_claims._scan_event_log(raw, token, queue._json)
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert found["unclaim_id"] == token
    assert peak < 128 * 1024, peak


class CountingBuffer(bytes):
    """Bytes whose ``find`` reports how many bytes each delimiter search examines."""

    def __new__(cls, data, budget):
        obj = bytes.__new__(cls, data)
        obj.examined = 0
        obj.budget = budget
        return obj

    def find(self, sub, start=0, end=None):
        if end is None:
            end = len(self)
        if start < 0:
            start = max(0, len(self) + start)
        found = bytes.find(self, sub, start, end)
        span = (end - start) if found < 0 else (found - start + len(sub))
        self.examined += span
        if self.examined > self.budget:
            raise RuntimeError("delimiter search exceeded the linear budget: %s > %s" % (
                self.examined, self.budget))
        return found


def _budget_log(case):
    cap = team_claims.MAX_EVENT_BYTES - team_claims.EVENT_MARGIN
    if case == "lf-rows":
        row = b'{"event":"lease_denied","result":"refused","detail":{}}\n'
        raw = row * (cap // len(row))
    elif case == "blank-lf":
        raw = b"\n" * 15728640
    elif case == "cr-rows":
        unit = b"{}\r"
        raw = unit * ((cap - 1) // len(unit)) + b"\n"
    else:
        raise AssertionError(case)
    assert 0 < len(raw) <= cap or case == "blank-lf"
    if case == "blank-lf":
        assert len(raw) == 15728640
    else:
        assert len(raw) > cap - 80
    return raw


@pytest.mark.parametrize("case", ["lf-rows", "blank-lf", "cr-rows"])
def test_event_row_delimiter_search_is_linear(case):
    raw = _budget_log(case)
    rows = raw.count(b"\n") + raw.count(b"\r")
    # Two full scans plus a few bytes of bookkeeping per row. A suffix rescan
    # exceeds this on the third row and aborts, so the quadratic shape cannot
    # run to the end of a 15 MiB log.
    budget = 2 * len(raw) + 8 * rows
    buf = CountingBuffer(raw, budget)
    produced = 0
    for _line in team_claims._iter_event_rows(buf):
        produced += 1
    assert buf.examined <= budget
    assert buf.examined >= len(raw)
    if case == "blank-lf":
        assert produced == 0
    elif case == "lf-rows":
        assert produced == raw.count(b"\n")
    else:
        assert produced == raw.count(b"\r")


@pytest.mark.timing
def test_blank_lf_receipt_scan_finishes_within_the_lock_timeout():
    raw = b"\n" * 15728640
    started = time.monotonic()
    assert list(team_claims._iter_event_rows(raw)) == []
    assert time.monotonic() - started < 5.0


def _assert_recovery_cause(result, category, *, lane=None, lease_oid=None):
    assert result["reason"] == "unclaim_recovery_required" and result["exit_code"] == 1, result
    assert [row["reason"] for row in result["blockers"]] == [
        "unclaim_recovery_required", category], result
    cause = result["blockers"][1]
    rendered = json.dumps(result)
    assert "private-value" not in rendered and "/tmp/secret" not in rendered
    assert "\n" not in json.dumps(cause)
    retry = result["blockers"][0]["next_action"]
    assert retry.startswith("Retry as the recorded caller: ")
    assert "--writer-stopped" in retry and "--workspace" in retry
    if category == "unclaim_lease_refused":
        assert cause["lane"] == lane and cause["lease_oid"] == lease_oid
        assert set(cause) == {"refused", "reason", "lane", "lease_oid", "next_action"}
        command = "aegis team release " + lane + " --expect " + lease_oid
        assert cause["next_action"].split(": ", 1)[1].startswith(command + " --workspace ")
        assert "unreadable" not in cause["next_action"]
    else:
        assert set(cause) == {"refused", "reason", "next_action"}
    return cause


def _append_correlated(root, pending, **overrides):
    body = {"unclaim_id": pending["to_revision"], "writer_stopped": True,
            "released_lease_ids": list(pending.get("released_lease_ids", []))}
    body.update(overrides)
    row = json.dumps({"event": "lease_claimed", "result": "queue_unclaim", "detail": body,
                      "note": "private-value"}, separators=(",", ":")).encode("ascii") + b"\n"
    log = events.events_path(root)
    original = log.read_bytes()
    log.write_bytes(original + row)
    return log, original


def _patch_gitsafe(monkeypatch, **methods):
    monkeypatch.setattr(team_claims, "gitsafe", SimpleNamespace(**{**vars(gitsafe), **methods}))


def _finish_without_attestation(root, path, revision, recovered):
    assert not recovered["refused"], recovered
    assert recovered["item"]["state"] == "queued"
    assert recovered["released_lease_ids"] == []
    assert "unclaim" not in json.loads(path.read_bytes())
    assert "private-value" not in json.dumps(recovered) and "/tmp/" not in json.dumps(recovered)
    rows = receipts(root)
    assert len(rows) == 1 and rows[0]["detail"]["released_lease_ids"] == []
    after = path.read_bytes()
    again = unclaim(root, recovered["item"]["revision"])
    assert again["reason"] == "not_claimed" and again["exit_code"] == 1
    assert path.read_bytes() == after
    assert team.read_leases(root).get("alpha") is None


@pytest.mark.parametrize("defect", ["writer-stopped", "released-ids"])
def test_inconsistent_receipt_names_event_cause(make_store, monkeypatch, defect):
    revision, oid, path = plant_pending(make_store, monkeypatch)
    before = path.read_bytes()
    pending = json.loads(before)["unclaim"]
    if defect == "writer-stopped":
        log, original = _append_correlated(make_store, pending, writer_stopped=False)
    else:
        log, original = _append_correlated(make_store, pending, released_lease_ids=["ab" * 20])
    for _ in range(2):
        result = unclaim(make_store, revision)
        _assert_recovery_cause(result, "unclaim_event_unavailable")
        assert path.read_bytes() == before
        assert "ab" * 20 not in json.dumps(result["blockers"])
    log.write_bytes(original)
    recovered = unclaim(make_store, revision)
    assert not recovered["refused"], recovered
    assert oid in recovered["released_lease_ids"]
    assert team.read_leases(make_store).get("alpha") is None


def test_concurrent_inconsistent_receipts_keep_the_event_cause(make_store, monkeypatch):
    revision, _oid, path = plant_pending(make_store, monkeypatch)
    before = path.read_bytes()
    pending = json.loads(before)["unclaim"]
    log, original = _append_correlated(make_store, pending, writer_stopped=False)
    with ProcessPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(race_unclaim, [(make_store, revision)] * 2, timeout=30))
    assert path.read_bytes() == before
    assert [result["reason"] for result in results] == ["unclaim_recovery_required"] * 2
    for result in results:
        _assert_recovery_cause(result, "unclaim_event_unavailable")
    log.write_bytes(original)
    recovered = unclaim(make_store, revision)
    assert not recovered["refused"], recovered


def test_receipt_while_lease_held_names_observed_oid(make_store, monkeypatch):
    revision, oid, path = plant_pending(make_store, monkeypatch)
    before = path.read_bytes()
    pending = json.loads(before)["unclaim"]
    log, original = _append_correlated(make_store, pending)
    for _ in range(2):
        result = unclaim(make_store, revision)
        _assert_recovery_cause(result, "unclaim_lease_refused", lane="alpha", lease_oid=oid)
        assert path.read_bytes() == before
    log.write_bytes(original)
    recovered = unclaim(make_store, revision)
    assert not recovered["refused"], recovered
    assert recovered["released_lease_ids"] == [oid]


def test_unconfirmed_release_names_lease_cause(make_store, monkeypatch):
    revision, oid, path = plant_pending(make_store, monkeypatch)
    before = path.read_bytes()

    def already(root, ref, new, old, single_attempt=False):
        return "already"

    _patch_gitsafe(monkeypatch, update_ref=already)
    for _ in range(2):
        result = unclaim(make_store, revision)
        _assert_recovery_cause(result, "unclaim_lease_refused", lane="alpha", lease_oid=oid)
        assert path.read_bytes() == before
        assert "already" not in json.dumps(result["blockers"])
    monkeypatch.setattr(team_claims, "gitsafe", gitsafe)
    recovered = unclaim(make_store, revision)
    assert not recovered["refused"], recovered
    assert recovered["released_lease_ids"] == [oid]


def test_absent_ref_between_release_reads_attests_nothing(make_store, monkeypatch):
    revision, oid, path = plant_pending(make_store, monkeypatch)
    real_read, real_update = gitsafe.read_ref, gitsafe.update_ref
    calls = {"n": 0}

    def read_ref(root, ref):
        if ref != team.lane_ref("alpha"):
            return real_read(root, ref)
        calls["n"] += 1
        if calls["n"] < 3:
            return real_read(root, ref)
        if calls["n"] == 3:
            real_update(root, ref, None, oid, single_attempt=True)
        return None

    _patch_gitsafe(monkeypatch, read_ref=read_ref)
    recovered = unclaim(make_store, revision)
    assert calls["n"] >= 3
    _finish_without_attestation(make_store, path, revision, recovered)


def test_refconflict_absent_ref_attests_nothing(make_store, monkeypatch):
    revision, oid, path = plant_pending(make_store, monkeypatch)
    real_update = gitsafe.update_ref

    def update_ref(root, ref, new, old, single_attempt=False):
        if ref == team.lane_ref("alpha") and new is None:
            real_update(root, ref, None, old, single_attempt=True)
            raise gitsafe.RefConflict("private-value /tmp/secret", ref=ref, expected=old, current=None)
        return real_update(root, ref, new, old, single_attempt=single_attempt)

    _patch_gitsafe(monkeypatch, update_ref=update_ref)
    recovered = unclaim(make_store, revision)
    _finish_without_attestation(make_store, path, revision, recovered)


def test_owner_release_between_reads_attests_nothing(make_store, monkeypatch):
    revision, oid, path = plant_pending(make_store, monkeypatch)
    real_read = gitsafe.read_ref
    calls = {"n": 0, "released": 0}

    def read_ref(root, ref):
        if ref != team.lane_ref("alpha"):
            return real_read(root, ref)
        calls["n"] += 1
        if calls["n"] < 3:
            return real_read(root, ref)
        if calls["n"] == 3:
            team.release(root, "alpha", oid, caller="owner")
            calls["released"] += 1
        return None

    _patch_gitsafe(monkeypatch, read_ref=read_ref)
    recovered = unclaim(make_store, revision)
    assert calls["released"] == 1 and calls["n"] >= 3
    _finish_without_attestation(make_store, path, revision, recovered)


def test_absent_lease_refusal_keeps_intent_oid(make_store, monkeypatch):
    revision, oid, path = plant_pending(make_store, monkeypatch)
    before = path.read_bytes()

    original = team_claims._release_lease

    def missing(*args, **kwargs):
        raise team.LeaseRefused("leak private-value /tmp/secret", "absent", "alpha", current=None)

    monkeypatch.setattr(team_claims, "_release_lease", missing)
    for _ in range(2):
        result = unclaim(make_store, revision)
        _assert_recovery_cause(result, "unclaim_lease_refused", lane="alpha", lease_oid=oid)
        assert path.read_bytes() == before
    monkeypatch.setattr(team_claims, "_release_lease", original)
    recovered = unclaim(make_store, revision)
    assert not recovered["refused"], recovered
    assert recovered["released_lease_ids"] == [oid]


_RETURN_TO_WORKSPACE = (
    "return to the workspace that issued this command; its path cannot be shown safely")


def _intent():
    return {"id": "ONE", "revision": "ab" * 32, "lane": "alpha", "caller": "owner",
            "reason": "Waiting", "lease_oid": None, "to_revision": "cd" * 32}


def _shell_command(text):
    """The shell command before an unquoted semicolon. Quoted semicolons stay put."""
    quote = None
    for index, char in enumerate(text):
        if quote:
            if char == quote:
                quote = None
            continue
        if char in "'\"":
            quote = char
            continue
        if char == ";":
            return text[:index]
    return text


def _workspace_token(text):
    argv = shlex.split(_shell_command(text))
    assert "--workspace" in argv, text
    return argv[argv.index("--workspace") + 1]


def _assert_identical_blocker_fields(blocker, intent):
    assert (blocker["caller"], blocker["revision"], blocker["reason_text"]) == (
        intent["caller"], intent["revision"], intent["reason"])
    assert blocker["item_id"] == intent["id"] and blocker["lane"] == intent["lane"]
    assert blocker["reason"] == "unclaim_recovery_required" and blocker["refused"] is True


def _assert_quoted_workspace(text, spelling):
    """The command carries one faithfully quoted ``--workspace`` and no joined line."""
    assert _RETURN_TO_WORKSPACE not in text, text
    token = _workspace_token(text)
    assert token == spelling
    assert shlex.split(shlex.quote(token)) == [token]
    shown = queue._shown(text)
    assert shown == text and len(shown) <= queue.MAX_TEXT and "\n" not in text


def _assert_shown_command(text, root):
    """A real root is quoted faithfully and resolves back to the workspace that issued it."""
    _assert_quoted_workspace(text, os.fspath(root))
    other = root.parent if root.parent != root else root
    assert resolve_cli_root(_workspace_token(text), other) == root.resolve()


def _assert_hidden_command(text, marker):
    """An unshowable path is omitted whole. Screening must not echo or join it."""
    assert "--workspace" not in text, text
    assert _RETURN_TO_WORKSPACE in text, text
    assert marker not in text
    assert "\n" not in text and "REDACTED" not in text
    shown = queue._shown(text)
    assert shown == text and marker not in shown


def test_windows_drive_less_recovery_path_requires_return(monkeypatch):
    monkeypatch.setattr(team_claims, "Path", PureWindowsPath)
    marker = "MARKERVALUE"
    refusal = team_claims.recovery_refusal(_intent(), root="/workspace/" + marker)
    _assert_hidden_command(refusal.blockers[0]["next_action"], marker)

    absolute = team_claims.recovery_refusal(_intent(), root="C:/workspace/plain")
    _assert_quoted_workspace(absolute.blockers[0]["next_action"], "C:/workspace/plain")


@pytest.mark.parametrize("shape", ["plain", "spaces", "quotes", "long", "credential", "overlong",
                                    "newline", "surrogate", "relative", "empty", "quoted-overflow",
                                    "display-overflow", "line-separator", "ansi", "components"])
def test_recovery_command_shape_matrix(shape):
    """Every recovery command names its workspace, or refuses to show the path."""
    intent = _intent()
    marker = "MARKERVALUE"
    anchor = "C:/" if os.name == "nt" else "/"
    if shape == "plain":
        root = anchor + "workspace/plain"
    elif shape == "spaces":
        root = anchor + "workspace/my work"
    elif shape == "quotes":
        root = anchor + "workspace/qu'ote"
    elif shape == "long":
        root = anchor + ("p" * 3000)
    elif shape == "credential":
        root = anchor + "tmp/token=" + marker
    elif shape == "overlong":
        root = anchor + (marker * 800)
    elif shape == "newline":
        root = anchor + "tmp/ab\n" + marker
    elif shape == "surrogate":
        root = anchor + "tmp/\udcff" + marker
    elif shape == "relative":
        root = "workspace/" + marker
    elif shape == "quoted-overflow":
        root = anchor + "workspace/" + ("'" * 1000) + marker
    elif shape == "display-overflow":
        root = anchor + "workspace/" + ("p" * queue.MAX_TEXT) + marker
    elif shape == "line-separator":
        root = anchor + "workspace/\u2028" + marker
    elif shape == "ansi":
        root = anchor + "workspace/\x1b[31m" + marker
    elif shape == "components":
        root = anchor + "workspace/" + ("part/" * 257) + marker
    else:
        root = ""
    show = shape in ("plain", "spaces", "quotes", "long")
    refusal = team_claims.recovery_refusal(intent, root=root)
    assert refusal.reason == "unclaim_recovery_required" and str(refusal) == refusal.reason
    blocker = refusal.blockers[0]
    _assert_identical_blocker_fields(blocker, intent)
    lease = team_claims._lease_refusal(root, "alpha", "ab" * 20)
    assert lease.reason == "unclaim_lease_refused"
    compact = team_claims.recovery_refusal(intent, root=root, cause="queue_size_limit")
    listed = team_claims.recovery_refusal(
        intent, root=root, cause="unclaim_lease_refused", lane="not a lane", lease_oid="nope")
    commands = (
        blocker["next_action"],
        lease.blockers[0]["next_action"],
        compact.blockers[1]["next_action"],
        listed.blockers[1]["next_action"],
    )
    for text in commands:
        if show:
            _assert_quoted_workspace(text, root)
        else:
            _assert_hidden_command(text, marker)
    if show:
        assert "aegis team queue unclaim" in blocker["next_action"]
        assert "aegis team release alpha --expect " + ("ab" * 20) in lease.blockers[0]["next_action"]
        assert "aegis team queue compact" in compact.blockers[1]["next_action"]
        assert "aegis team list --json" in listed.blockers[1]["next_action"]
        assert "not a lane" not in listed.blockers[1]["next_action"]
        assert "nope" not in json.dumps(listed.blockers[1])
    else:
        rendered = json.dumps(refusal.blockers)
        assert marker not in rendered and "REDACTED" not in rendered


def test_recovery_commands_from_a_real_workspace_resolve_back(make_store, tmp_path):
    """Public refusals carry the issuing root, including spaces and quotes."""
    quoted = tmp_path / "my work" / "qu'ote"
    quoted.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(quoted)], check=True)
    (quoted / ".aegis").mkdir()
    (quoted / ".aegis" / "team.json").write_text(json.dumps({
        "v": 1, "lanes": {"alpha": ["src/**"]}}), encoding="utf-8")
    for root in (make_store, quoted):
        added = queue.add(root, {"id": "ONE", "title": "Work", "paths": ["src/**"], "capabilities": []}, now=100)
        claimed = queue.claim(root, "ONE", expect=added["item"]["revision"], lane="alpha", now=101, caller="owner")
        assert not claimed["refused"], claimed
        team.claim(root, "alpha", ["src/**"], owner="owner", now=100)
        original = team_claims._release_lease

        def failed(*args, **kwargs):
            raise OSError("injected")

        # The module attribute is the one transition calls. Patch that, not os.open.
        team_claims._release_lease = failed
        try:
            first = unclaim(root, claimed["item"]["revision"], reason="Waiting")
            again = queue.list(root, now=102)
        finally:
            team_claims._release_lease = original
        assert first["reason"] == "unclaim_recovery_required"
        for result in (first, again):
            blocker = result["blockers"][0]
            assert (blocker["caller"], blocker["revision"], blocker["reason_text"]) == (
                "owner", claimed["item"]["revision"], "Waiting")
            _assert_shown_command(blocker["next_action"], root)
        assert queue.list(root, now=103)["reason"] == "unclaim_recovery_required"
        recovered = unclaim(root, claimed["item"]["revision"])
        assert not recovered["refused"], recovered


def test_pending_verbs_from_another_directory_name_the_issuing_workspace(make_store, tmp_path):
    """list, audit and another verb refuse with a command that resolves to this root."""
    added = queue.add(make_store, {"id": "ONE", "title": "Work", "paths": ["src/**"], "capabilities": []}, now=100)
    claimed = queue.claim(make_store, "ONE", expect=added["item"]["revision"], lane="alpha",
                          now=101, caller="owner", branch="lane/alpha")
    path = make_store / ".aegis" / "state" / "team-queue.json"
    state = json.loads(path.read_text(encoding="utf-8"))
    state["unclaim"] = {"id": "ONE", "revision": claimed["item"]["revision"], "lane": "alpha",
                        "caller": "owner", "reason": "Waiting", "lease_oid": None, "to_revision": "ab" * 32}
    path.write_text(json.dumps(state), encoding="utf-8")
    other = tmp_path / "elsewhere"
    other.mkdir()
    previous = os.getcwd()
    os.chdir(other)
    try:
        listed = queue.list(make_store, now=102)
        audited = queue.audit(make_store, now=102)
        released = queue.release(make_store, "ONE", expect=claimed["item"]["revision"], lane="alpha", now=102)
    finally:
        os.chdir(previous)
    for result in (listed, audited, released):
        assert result["reason"] == "unclaim_recovery_required" and result["exit_code"] == 1
        blocker = result["blockers"][0]
        assert blocker["reason_text"] == "Waiting" and blocker["caller"] == "owner"
        _assert_shown_command(blocker["next_action"], make_store)
        assert os.fspath(other) not in blocker["next_action"]
    assert "unclaim" in json.loads(path.read_text(encoding="utf-8"))


def test_read_only_list_without_pending_unclaim_emits_no_recovery_command(make_store):
    added = queue.add(make_store, {"id": "ONE", "title": "Work", "paths": ["src/**"], "capabilities": []}, now=100)
    assert not added["refused"], added
    listed = queue.list(make_store, now=101)
    rendered = json.dumps(listed)
    assert listed["refused"] is False
    assert "aegis team queue unclaim" not in rendered
    assert "--workspace" not in rendered
    from aegis_mcp.tools import execute_tool
    mcp = execute_tool("aegis_team_queue", {"workspace": make_store})
    mcp_text = json.dumps(mcp)
    assert mcp["refused"] is False
    assert "aegis team queue unclaim" not in mcp_text
    assert "--workspace" not in mcp_text
