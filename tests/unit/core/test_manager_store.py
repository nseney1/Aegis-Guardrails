"""Public manager audit storage: strict replay, bounded writes and isolated placement."""
from __future__ import annotations

import hashlib
import errno
import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

from aegis_core.manager_policy import ManagerError
from aegis_core.manager_store import MAX_AUDIT_BYTES, MAX_ROW_BYTES, ManagerStore, in_git_worktree, resolve_placement_path
from tests.conftest import symlink_or_skip
from tests.helpers_manager import manager_root as tmp_path
from tests.helpers_manager import GIT_PLACEMENT_NAMES, missing_traversal_path, unsearchable_manager_alias

REPO = Path(__file__).resolve().parents[3]


def _encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def _absent_external_path():
    anchor = Path(Path.cwd().anchor)
    if os.path.lexists(anchor / ".git"):
        pytest.skip("filesystem anchor already has a .git marker")
    root = anchor / ("aegis-rf91-absent-" + uuid.uuid4().hex)
    assert not root.exists()
    return root


@pytest.mark.parametrize("name", GIT_PLACEMENT_NAMES)
@pytest.mark.parametrize("position", ["final", "intermediate"])
def test_in_git_worktree_refuses_uncreated_git_components(name, position):
    root = _absent_external_path()
    parts = (name,) if position == "final" else (name, "file")
    assert in_git_worktree(root.joinpath(*parts)) is True
    assert not root.exists()


def test_in_git_worktree_accepts_absent_external_path_without_manager_fixture():
    assert in_git_worktree(_absent_external_path() / "missing" / "audit") is False


def test_in_git_worktree_accepts_existing_external_directory_without_manager_fixture():
    root = _absent_external_path().parent
    assert in_git_worktree(root) is False


@pytest.mark.parametrize("operation", [in_git_worktree, resolve_placement_path])
@pytest.mark.parametrize("unsafe_code", ["unsafe_store", "unsafe_config"])
def test_placement_refuses_missing_parent_traversal(missing_traversal_path, operation, unsafe_code):
    with pytest.raises(ManagerError, match="^" + unsafe_code + "$") as refusal:
        operation(missing_traversal_path, unsafe_code=unsafe_code)
    assert refusal.value.path == missing_traversal_path


@pytest.mark.parametrize("operation", [in_git_worktree, resolve_placement_path])
@pytest.mark.parametrize("unsafe_code", ["unsafe_store", "unsafe_config"])
def test_placement_refuses_dot_before_metadata(monkeypatch, operation, unsafe_code):
    from aegis_core import manager_store

    def unexpected_lstat(*args, **kwargs):
        pytest.fail("dot placement inspected filesystem metadata")

    monkeypatch.setattr(manager_store, "os", SimpleNamespace(**{**vars(manager_store.os), "lstat": unexpected_lstat}))
    with pytest.raises(ManagerError, match="^" + unsafe_code + "$") as refusal:
        operation(Path("."), unsafe_code=unsafe_code)
    assert refusal.value.path == Path(".")


@pytest.mark.parametrize("operation", ["read", "append", "transaction"])
def test_store_refuses_missing_parent_traversal(missing_traversal_path, operation):
    with pytest.raises(ManagerError, match="^unsafe_store$"):
        store = ManagerStore(missing_traversal_path)
        if operation == "read":
            store.read()
        elif operation == "append":
            store.append({"kind": "scan"})
        else:
            store.transaction(lambda rows: pytest.fail("traversal invoked callback"))


@pytest.mark.parametrize("error", [errno.EACCES, errno.ELOOP, errno.ENAMETOOLONG, errno.EIO])
@pytest.mark.parametrize("stage", ["prefix", "marker"])
def test_placement_metadata_errors_are_unsafe_store(monkeypatch, error, stage):
    from aegis_core import manager_store

    root = _absent_external_path() / "audit"
    real_os = manager_store.os

    def failing_lstat(path, *args, **kwargs):
        if (stage == "prefix" and Path(path) == root) or (stage == "marker" and Path(path).name == ".git"):
            raise OSError(error, "simulated placement metadata failure")
        return real_os.lstat(path, *args, **kwargs)

    monkeypatch.setattr(manager_store, "os", SimpleNamespace(**{**vars(real_os), "lstat": failing_lstat}))
    with pytest.raises(ManagerError, match="^unsafe_store$"):
        in_git_worktree(root)


def test_store_symlink_loop_is_unsafe(tmp_path_factory):
    root = tmp_path_factory.mktemp("loop-placement")
    loop = root / "loop"
    symlink_or_skip("loop", loop, target_is_directory=True)
    with pytest.raises(ManagerError, match="^unsafe_store$"):
        ManagerStore(loop / "audit").append({"kind": "scan"})
    assert list(root.iterdir()) == [loop]
    assert not (root / ".git").exists()


@pytest.mark.parametrize("operation", ["helper", "append"])
def test_unsearchable_prefix_is_unsafe_store(unsearchable_manager_alias, operation):
    path = unsearchable_manager_alias / "audit"
    with pytest.raises(ManagerError, match="^unsafe_store$"):
        if operation == "helper":
            in_git_worktree(path)
        else:
            ManagerStore(path).append({"kind": "scan"})
    target = unsearchable_manager_alias.parent.parent / "repo" / "sub"
    assert list(target.iterdir()) == []


@pytest.mark.parametrize("marker", ["directory", "gitfile"])
def test_in_git_worktree_resolves_directory_alias(tmp_path, marker):
    repo = tmp_path / "repo"
    target = repo / "sub"
    target.mkdir(parents=True)
    if marker == "directory":
        (repo / ".git").mkdir()
    else:
        (repo / ".git").write_text("gitdir: absent\n", encoding="utf-8")
    alias = tmp_path / "alias"
    symlink_or_skip(target, alias, target_is_directory=True)
    assert in_git_worktree(alias / "missing" / "audit") is True


def test_in_git_worktree_resolves_proc_cwd_alias(tmp_path_factory, monkeypatch):
    alias = Path("/proc/self/cwd")
    if os.name != "posix" or not alias.is_dir():
        pytest.skip("requires /proc/self/cwd")
    repo = tmp_path_factory.mktemp("physical-placement")
    (repo / ".git").mkdir()
    child = repo / "sub"
    child.mkdir()
    monkeypatch.chdir(child)
    assert in_git_worktree(alias / "missing" / "audit") is True


@pytest.mark.parametrize("name", GIT_PLACEMENT_NAMES)
@pytest.mark.parametrize("position", ["final", "intermediate"])
@pytest.mark.parametrize("operation", ["append", "transaction"])
def test_store_refuses_git_components_before_creating_anything(tmp_path, name, position, operation):
    root = tmp_path / "missing"
    parts = (name,) if position == "final" else (name, "audit")
    store = ManagerStore(root.joinpath(*parts))
    with pytest.raises(ManagerError, match="^store_in_worktree$"):
        if operation == "append":
            store.append({"kind": "scan"})
        else:
            store.transaction(lambda rows: pytest.fail("reserved placement invoked callback"))
    assert not root.exists()
    assert not (root / ".git").exists()


def test_reads_do_not_initialize_store(tmp_path):
    root = tmp_path / "audit"
    assert ManagerStore(root).read() == []
    assert not root.exists()


def test_append_replays_identical_chain_after_restart(tmp_path):
    root = tmp_path / "audit"
    store = ManagerStore(root)
    first = store.append({"kind": "scan", "decision": "one"})
    second = store.append({"kind": "report", "claim": "success"})
    assert first["seq"] == 1 and first["prev"] == "0" * 64
    assert second["seq"] == 2 and second["prev"] == first["hash"]
    for row in (first, second):
        body = {key: value for key, value in row.items() if key != "hash"}
        assert row["hash"] == hashlib.sha256(_encoded(body)).hexdigest()
    assert ManagerStore(root).read() == [first, second]
    if os.name == "posix":
        assert root.stat().st_mode & 0o777 == 0o700
        assert (root / "audit.jsonl").stat().st_mode & 0o777 == 0o600
        assert (root / "audit.lock").stat().st_mode & 0o777 == 0o600


def test_transactions_return_result_and_can_decline_append(tmp_path):
    store = ManagerStore(tmp_path / "audit")
    assert store.transaction(lambda rows: ({"kind": "scan"}, "created")) == "created"
    original = (store.root / "audit.jsonl").read_bytes()
    assert store.transaction(lambda rows: (None, rows[0]["kind"])) == "scan"
    assert (store.root / "audit.jsonl").read_bytes() == original


def test_transaction_cannot_mutate_persisted_history(tmp_path):
    store = ManagerStore(tmp_path / "audit")
    first = store.append({"kind": "scan"})

    def callback(rows):
        rows[0]["hash"] = "f" * 64
        return {"kind": "report"}, None

    store.transaction(callback)
    assert store.read()[1]["prev"] == first["hash"]


@pytest.mark.parametrize("payload", [None, [], {"seq": 9}, {"hash": "forged"}, {"prev": "forged"}, {"bad": float("nan")}])
def test_invalid_events_write_nothing(tmp_path, payload):
    store = ManagerStore(tmp_path / "audit")
    with pytest.raises(ManagerError, match="^invalid_event$"):
        store.append(payload)
    assert store.read() == []


def test_callback_failure_preserves_history(tmp_path):
    store = ManagerStore(tmp_path / "audit")
    store.append({"kind": "scan"})
    original = (store.root / "audit.jsonl").read_bytes()

    def callback(rows):
        raise RuntimeError("callback failed")

    with pytest.raises(RuntimeError, match="^callback failed$"):
        store.transaction(callback)
    assert (store.root / "audit.jsonl").read_bytes() == original


@pytest.mark.parametrize("suffix", [b'{"torn":', b"\n", b'{"hash":"bad"}\n', b'null\n', b'\xff\n'])
def test_corruption_is_explicit_and_never_repaired(tmp_path, suffix):
    store = ManagerStore(tmp_path / "audit")
    store.append({"kind": "scan"})
    path = store.root / "audit.jsonl"
    original = path.read_bytes() + suffix
    path.write_bytes(original)
    with pytest.raises(ManagerError, match="^audit_corrupt$"):
        store.read()
    with pytest.raises(ManagerError, match="^audit_corrupt$"):
        store.append({"kind": "report"})
    assert path.read_bytes() == original


def test_reordered_or_changed_history_is_rejected(tmp_path):
    store = ManagerStore(tmp_path / "audit")
    store.append({"kind": "scan", "claim": "one"})
    store.append({"kind": "report", "claim": "two"})
    path = store.root / "audit.jsonl"
    raw = path.read_bytes()
    lines = raw.splitlines(keepends=True)
    for bad in (b"".join(reversed(lines)), raw.replace(b'"one"', b'"tampered"')):
        path.write_bytes(bad)
        with pytest.raises(ManagerError, match="^audit_corrupt$"):
            store.read()


def test_duplicate_json_keys_are_corruption(tmp_path):
    store = ManagerStore(tmp_path / "audit")
    store.append({"kind": "scan"})
    path = store.root / "audit.jsonl"
    path.write_bytes(path.read_bytes().replace(b'"kind":"scan"', b'"kind":"scan","kind":"scan"'))
    with pytest.raises(ManagerError, match="^audit_corrupt$"):
        store.read()


def test_row_and_store_limits_do_not_append(tmp_path):
    store = ManagerStore(tmp_path / "audit")
    with pytest.raises(ManagerError, match="^audit_limit$"):
        store.append({"large": "x" * MAX_ROW_BYTES})
    assert store.read() == []
    store.append({"kind": "scan"})
    path = store.root / "audit.jsonl"
    with path.open("ab") as handle:
        handle.truncate(MAX_AUDIT_BYTES + 1)
    original_size = path.stat().st_size
    with pytest.raises(ManagerError, match="^audit_limit$"):
        store.read()
    assert path.stat().st_size == original_size


def test_forbidden_worktree_placement(tmp_path):
    worktree = tmp_path / "implementation"
    worktree.mkdir()
    with pytest.raises(ManagerError, match="^store_in_worktree$"):
        ManagerStore(worktree / "audit", forbidden_roots=[worktree]).append({"kind": "scan"})
    assert not (worktree / "audit").exists()


@pytest.mark.parametrize("marker", ["directory", "file"])
def test_git_worktree_placement_rejected_without_discovery(tmp_path, marker):
    worktree = tmp_path / "implementation"
    worktree.mkdir()
    if marker == "directory":
        (worktree / ".git").mkdir()
    else:
        (worktree / ".git").write_text("gitdir: elsewhere\n")
    with pytest.raises(ManagerError, match="^store_in_worktree$"):
        ManagerStore(worktree / "nested" / "audit").append({"kind": "scan"})
    assert not (worktree / "nested").exists()


def test_symlink_root_or_ancestor_is_rejected(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    link = tmp_path / "link"
    symlink_or_skip(outside, link, target_is_directory=True)
    for root in (link, link / "nested"):
        with pytest.raises(ManagerError, match="^unsafe_store$"):
            ManagerStore(root).append({"kind": "scan"})
    assert list(outside.iterdir()) == []


@pytest.mark.parametrize("name", ["audit.lock", "audit.jsonl"])
@pytest.mark.parametrize("kind", ["symlink", "hardlink", "directory"])
def test_nonprivate_store_entries_are_rejected(tmp_path, name, kind):
    root = tmp_path / "audit"
    root.mkdir(mode=0o700)
    outside = tmp_path / "outside"
    outside.write_bytes(b"do not change\n")
    target = root / name
    if kind == "symlink":
        symlink_or_skip(outside, target)
    elif kind == "hardlink":
        os.link(outside, target)
    else:
        target.mkdir()
    with pytest.raises(ManagerError, match="^unsafe_store$"):
        ManagerStore(root).append({"kind": "scan"})
    assert outside.read_bytes() == b"do not change\n"


def test_world_readable_store_is_rejected(tmp_path):
    if os.name != "posix":
        pytest.skip("POSIX permissions")
    root = tmp_path / "audit"
    root.mkdir(mode=0o755)
    with pytest.raises(ManagerError, match="^unsafe_store$"):
        ManagerStore(root).append({"kind": "scan"})


def test_concurrent_processes_preserve_every_event_and_chain(tmp_path):
    root = tmp_path / "audit"
    worker = """
import os
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from aegis_core.manager_store import ManagerStore
phase, item = "construct", None
try:
    store = ManagerStore(Path(sys.argv[2]))
    phase = "append"
    for item in range(12):
        store.append({"worker": sys.argv[3], "item": item})
except BaseException:
    print(f"worker={sys.argv[3]} pid={os.getpid()} phase={phase} item={item} root={sys.argv[2]}",
          file=sys.stderr, flush=True)
    raise
"""
    processes = [subprocess.Popen([sys.executable, "-I", "-c", worker, str(REPO), str(root), str(n)],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for n in range(4)]
    try:
        for process in processes:
            stdout, stderr = process.communicate(timeout=30)
            if process.returncode != 0:
                pytest.fail(f"worker exit={process.returncode}\nstdout:\n{stdout}\nstderr:\n{stderr}",
                            pytrace=False)
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=5)
    rows = ManagerStore(root).read()
    assert len(rows) == 48
    assert [row["seq"] for row in rows] == list(range(1, 49))
    assert {(row["worker"], row["item"]) for row in rows} == {(str(n), i) for n in range(4) for i in range(12)}


def test_lock_timeout_is_explicit(tmp_path):
    root = tmp_path / "audit"
    ManagerStore(root).append({"kind": "scan"})
    worker = ("import sys; sys.path.insert(0, sys.argv[1]); "
              "from pathlib import Path; from aegis_core import storage; "
              "lock=storage.file_lock(Path(sys.argv[2])/'audit.lock'); lock.__enter__(); "
              "Path(sys.argv[2],'ready').touch(); sys.stdin.readline(); lock.__exit__(None,None,None)")
    process = subprocess.Popen([sys.executable, "-I", "-c", worker, str(REPO), str(root)],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        deadline = time.monotonic() + 5
        while not (root / "ready").exists() and process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.01)
        assert (root / "ready").exists(), "lock worker did not become ready"
        with pytest.raises(ManagerError, match="^store_busy$"):
            ManagerStore(root).append({"kind": "report"})
    finally:
        process.communicate(input="release\n", timeout=10)
    assert process.returncode == 0
    assert len(ManagerStore(root).read()) == 1


def test_reentrant_callback_cannot_create_a_stale_chain(tmp_path):
    store = ManagerStore(tmp_path / "audit")
    store.append({"kind": "scan"})

    def callback(rows):
        store.append({"kind": "nested"})
        return {"kind": "outer"}, None

    with pytest.raises(ManagerError, match="^audit_conflict$"):
        store.transaction(callback)
    assert [row["kind"] for row in store.read()] == ["scan", "nested"]


def test_partial_os_write_preserves_raw_uncertainty(tmp_path, monkeypatch):
    store = ManagerStore(tmp_path / "audit")
    store.append({"kind": "scan"})
    original = (store.root / "audit.jsonl").read_bytes()
    real_write = os.write
    calls = []

    def broken_write(fd, data):
        if calls:
            raise OSError("simulated disk failure")
        calls.append(True)
        return real_write(fd, data[:5])

    with monkeypatch.context() as patch:
        patch.setattr(os, "write", broken_write)
        with pytest.raises(OSError, match="^simulated disk failure$"):
            store.append({"kind": "report"})
    torn = (store.root / "audit.jsonl").read_bytes()
    assert torn.startswith(original) and len(torn) == len(original) + 5
    with pytest.raises(ManagerError, match="^audit_corrupt$"):
        store.read()
    assert (store.root / "audit.jsonl").read_bytes() == torn


@pytest.mark.parametrize("field,value", [("seq", True), ("seq", 2), ("prev", "f" * 64), ("hash", "g" * 64)])
def test_invalid_envelopes_are_rejected_even_when_json_is_valid(tmp_path, field, value):
    store = ManagerStore(tmp_path / "audit")
    row = store.append({"kind": "scan"})
    row[field] = value
    (store.root / "audit.jsonl").write_bytes(_encoded(row) + b"\n")
    with pytest.raises(ManagerError, match="^audit_corrupt$"):
        store.read()


def test_ancestor_swap_before_directory_open_cannot_write_outside(tmp_path, monkeypatch):
    if os.name != "posix":
        pytest.skip("POSIX descriptor anchoring")
    parent = tmp_path / "parent"
    parent.mkdir(mode=0o700)
    root = parent / "audit"
    store = ManagerStore(root)
    store.append({"kind": "scan"})
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    (outside / "audit").mkdir(mode=0o700)
    real_open = os.open
    swapped = []

    def swap_open(path, flags, *args, **kwargs):
        if Path(path) in (root, Path("audit")) and flags & os.O_DIRECTORY and not swapped:
            swapped.append(True)
            parent.rename(tmp_path / "original-parent")
            symlink_or_skip(outside, parent, target_is_directory=True)
        return real_open(path, flags, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(os, "open", swap_open)
        patch.setattr(os, "supports_dir_fd", os.supports_dir_fd | {swap_open})
        with pytest.raises(ManagerError, match="^unsafe_store$"):
            store.append({"kind": "report"})
    assert swapped
    assert not (outside / "audit" / "audit.jsonl").exists()


def test_public_lock_descriptor_stays_in_original_directory(tmp_path):
    if os.name != "posix":
        pytest.skip("POSIX descriptor anchoring")
    from aegis_core import storage
    parent = tmp_path / "parent"
    parent.mkdir(mode=0o700)
    root = parent / "audit"
    root.mkdir(mode=0o700)
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    (outside / "audit").mkdir(mode=0o700)
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    parent.rename(tmp_path / "original-parent")
    symlink_or_skip(outside, parent, target_is_directory=True)
    try:
        with storage.file_lock(root / "audit.lock", dir_fd=descriptor):
            assert (tmp_path / "original-parent" / "audit" / "audit.lock").exists()
            assert not (outside / "audit" / "audit.lock").exists()
    finally:
        os.close(descriptor)


def test_ancestor_swap_before_lock_open_cannot_write_outside(tmp_path, monkeypatch):
    if os.name != "posix":
        pytest.skip("POSIX descriptor anchoring")
    parent = tmp_path / "parent"
    parent.mkdir(mode=0o700)
    root = parent / "audit"
    store = ManagerStore(root)
    store.append({"kind": "scan"})
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    (outside / "audit").mkdir(mode=0o700)
    real_open = os.open
    swapped = []

    def swap_open(path, flags, *args, **kwargs):
        if Path(path).name == "audit.lock" and not swapped:
            swapped.append(True)
            parent.rename(tmp_path / "original-parent")
            symlink_or_skip(outside, parent, target_is_directory=True)
        return real_open(path, flags, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(os, "open", swap_open)
        patch.setattr(os, "supports_dir_fd", os.supports_dir_fd | {swap_open})
        with pytest.raises(ManagerError, match="^unsafe_store$"):
            store.append({"kind": "report"})
    assert swapped
    assert not (outside / "audit" / "audit.lock").exists()
    assert not (outside / "audit" / "audit.jsonl").exists()


def test_ancestor_swap_before_mkdir_cannot_create_outside(tmp_path, monkeypatch):
    if os.name != "posix":
        pytest.skip("POSIX descriptor anchoring")
    parent = tmp_path / "parent"
    parent.mkdir(mode=0o700)
    root = parent / "audit"
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    real_mkdir = os.mkdir
    swapped = []

    def swap_mkdir(path, *args, **kwargs):
        if Path(path).name == "audit" and not swapped:
            swapped.append(True)
            parent.rename(tmp_path / "original-parent")
            symlink_or_skip(outside, parent, target_is_directory=True)
        return real_mkdir(path, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(os, "mkdir", swap_mkdir)
        with pytest.raises(ManagerError, match="^unsafe_store$"):
            ManagerStore(root).append({"kind": "scan"})
    assert swapped
    assert not (outside / "audit").exists()


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "directory"])
def test_public_lock_descriptor_refuses_unsafe_final_entry(tmp_path, kind):
    if os.name != "posix":
        pytest.skip("POSIX descriptor anchoring")
    from aegis_core import storage
    from aegis_core.errors import PathTraversalError
    root = tmp_path / "audit"
    root.mkdir(mode=0o700)
    outside = tmp_path / "outside"
    outside.write_bytes(b"retain bytes\n")
    original_mode = outside.stat().st_mode
    if kind == "symlink":
        symlink_or_skip(outside, root / "audit.lock")
    elif kind == "hardlink":
        os.link(outside, root / "audit.lock")
    else:
        (root / "audit.lock").mkdir()
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(PathTraversalError), storage.file_lock(root / "audit.lock", dir_fd=descriptor):
            pytest.fail("unsafe lock admitted")
        assert os.fstat(descriptor).st_ino == root.stat().st_ino
    finally:
        os.close(descriptor)
    assert outside.read_bytes() == b"retain bytes\n"
    assert outside.stat().st_mode == original_mode
