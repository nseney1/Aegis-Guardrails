"""Moved shared-state code keeps the original storage module's live patch targets."""
from __future__ import annotations

import os
import json
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest

from aegis_core import storage
from aegis_core.errors import PathTraversalError
from aegis_core.verification import call_graph
from aegis_cli.cli import main
from tests import helpers_humangate as hg


@pytest.mark.parametrize("fast_mode", [False, True])
def test_storage_helpers_need_no_repository_search(monkeypatch, fast_mode):
    def unexpected_search(*args, **kwargs):
        pytest.fail("storage helpers must have call sites without searching the repository")

    monkeypatch.setattr(call_graph, "_get_searchable_source_files", unexpected_search)
    root = Path(__file__).resolve().parents[3]
    result = call_graph.check(str(root / "aegis_core" / "storage.py"), str(root), fast_mode=fast_mode)
    assert result.verdict is True, result.detail
    assert "external candidates skipped" not in result.detail


@pytest.mark.parametrize("path", ["aegis_core/storage.py", "aegis_core/storage_shared.py",
                                 "tests/unit/core/test_storage_shared.py"])
def test_public_scan_covers_storage_confinement(tmp_path, monkeypatch, capsys, path):
    root = Path(__file__).resolve().parents[3]
    workspace = tmp_path / "workspace"
    for relative in ("contracts/contract-atomic-storage-boundaries.md",
                     "invariants/invariant-single-canonical-ledger.md"):
        source = root / ".aegis" / "rules" / relative
        destination = workspace / ".aegis" / "rules" / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
    monkeypatch.chdir(workspace)
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    assert main(["scan", path, "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert {rule["name"] for rule in payload["relevant_rules"]} == {
        "contract-atomic-storage-boundaries", "invariant-single-canonical-ledger"}


def test_bound_storage_namespace_preserves_live_patch_targets(tmp_path, monkeypatch):
    expected = tmp_path / "patched-state"
    monkeypatch.setattr(storage, "sys", SimpleNamespace(modules={}))
    monkeypatch.setattr(storage, "gitsafe", SimpleNamespace(common_dir=lambda root: None))
    monkeypatch.setattr(storage, "state_dir", lambda root: expected)
    assert storage.shared_state_dir(tmp_path) == expected


@pytest.fixture
def repo(tmp_path):
    if not hg.git_ok():
        pytest.skip("needs git")
    return hg.make_repo(tmp_path).root


def test_is_within_patch_refuses_shared_state(repo, monkeypatch):
    storage.shared_state_dir(repo)
    monkeypatch.setattr(storage, "is_within", lambda *args, **kwargs: False)
    with pytest.raises(PathTraversalError, match="resolves outside") as caught:
        storage.shared_state_dir(repo, create=False)
    assert caught.value.code == "ERR_PATH_TRAVERSAL"


@pytest.mark.parametrize("name", ["_confined", "_shared_errors", "_confined_shared", "_shared_dir"])
def test_private_confinement_hooks_remain_live(repo, monkeypatch, name):
    directory = storage.shared_state_dir(repo)
    assert directory.is_dir()

    def refuse(*args, **kwargs):
        raise PathTraversalError("shared confinement refused")

    monkeypatch.setattr(storage, name, refuse)
    with pytest.raises(PathTraversalError, match="^shared confinement refused$"):
        storage.shared_state_dir(repo, create=False)


@pytest.mark.parametrize("name,index", [("_shared_link_error", 0), ("_shared_outside_error", 1)])
def test_error_closures_look_up_patched_factories_at_call_time(tmp_path, monkeypatch, name, index):
    handlers = storage._shared_errors(tmp_path)
    refusal = PathTraversalError("patched refusal")
    monkeypatch.setattr(storage, name, lambda path, base: refusal)
    assert handlers[index](tmp_path / "entry") is refusal


@pytest.mark.parametrize("name", ["_shared_link_error", "_shared_outside_error"])
def test_refusal_type_is_read_from_storage(tmp_path, monkeypatch, name):
    class PatchedRefusal(PathTraversalError):
        pass

    monkeypatch.setattr(storage, "PathTraversalError", PatchedRefusal)
    refusal = getattr(storage, name)(tmp_path / "entry", tmp_path)
    assert type(refusal) is PatchedRefusal
    assert refusal.code == "ERR_PATH_TRAVERSAL"


def test_lock_name_hook_is_read_from_storage(tmp_path, monkeypatch):
    def refuse(name):
        raise ValueError("patched lock name")

    monkeypatch.setattr(storage, "_shared_lock_name", refuse)
    with pytest.raises(ValueError, match="^patched lock name$"):
        with storage.shared_locked(tmp_path, "events.lock"):
            pytest.fail("the refusal must precede lock acquisition")


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission audit")
def test_path_constructor_is_read_from_storage(tmp_path, monkeypatch):
    calls = []

    def make_path(value):
        calls.append(value)
        return Path(value)

    monkeypatch.setattr(storage, "Path", make_path)
    monkeypatch.setattr(storage, "gitsafe", SimpleNamespace(common_dir=lambda root: None))
    storage.shared_state_modes(tmp_path)
    assert calls == [os.fspath(tmp_path)]


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission audit")
def test_git_lookup_is_read_from_storage(tmp_path, monkeypatch):
    calls = []

    def common_dir(root):
        calls.append(root)
        return None

    monkeypatch.setattr(storage, "gitsafe", SimpleNamespace(common_dir=common_dir))
    assert storage.shared_state_modes(tmp_path) == storage.StateModes(0, 0, 0, True)
    assert calls == [tmp_path.resolve()]


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission audit")
def test_real_path_is_read_from_storage(repo, monkeypatch):
    common = storage.gitsafe.common_dir(repo)
    original = storage.real_path
    calls = []

    def resolve(path):
        calls.append(path)
        return original(path)

    monkeypatch.setattr(storage, "real_path", resolve)
    storage.shared_state_modes(repo)
    assert calls == [common]


def test_workspace_layout_is_read_from_storage(tmp_path, monkeypatch):
    def refuse(root):
        raise PathTraversalError("patched layout")

    monkeypatch.setattr(storage, "gitsafe", SimpleNamespace(common_dir=lambda root: None))
    monkeypatch.setattr(storage, "WorkspaceLayout", refuse)
    with pytest.raises(PathTraversalError, match="^patched layout$"):
        storage.shared_state_dir(tmp_path, create=False)


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
@pytest.mark.parametrize("directory_mode", [0o700, 0o710])
def test_chmod_and_directory_mode_patches_reach_audit(repo, monkeypatch, directory_mode):
    directory = storage.shared_state_dir(repo)
    os.chmod(directory, 0o755)
    calls = []

    def refuse_chmod(path, mode, is_dir):
        calls.append((path, mode, is_dir))
        return False

    monkeypatch.setattr(storage, "_chmod_exact", refuse_chmod)
    monkeypatch.setattr(storage, "_SHARED_DIR_MODE", directory_mode)
    assert storage.shared_state_modes(repo, fix=True) == storage.StateModes(1, 1, 0, True)
    assert calls == [(directory, directory_mode, True)]
    assert stat.S_IMODE(directory.stat().st_mode) == 0o755


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_shared_directory_creation_uses_patched_mode(repo, monkeypatch):
    monkeypatch.setattr(storage, "_SHARED_DIR_MODE", 0o710)
    directory = storage.shared_state_dir(repo)
    assert stat.S_IMODE(directory.stat().st_mode) == 0o710


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_stat_is_read_from_storage(repo, monkeypatch):
    directory = storage.shared_state_dir(repo)
    os.chmod(directory, 0o755)
    calls = []
    monkeypatch.setattr(storage, "stat", SimpleNamespace(S_IMODE=lambda mode: calls.append(mode) or 0))
    assert storage.shared_state_modes(repo) == storage.StateModes(1, 0, 0, True)
    assert len(calls) == 1


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_private_file_mode_is_read_from_storage(repo, monkeypatch):
    directory = storage.shared_state_dir(repo)
    path = directory / "entry.json"
    path.write_text("{}", encoding="utf-8")
    os.chmod(path, 0o666)
    calls = []
    monkeypatch.setattr(storage, "_PRIVATE_FILE_MODE", 0o640)
    monkeypatch.setattr(storage, "_chmod_exact", lambda *args: calls.append(args) or False)
    assert storage.shared_state_modes(repo, fix=True) == storage.StateModes(2, 1, 0, True)
    assert calls == [(path, 0o640, False)]


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission audit")
def test_shared_directory_hook_is_used_by_audit(repo, monkeypatch):
    def refuse(*args, **kwargs):
        raise PathTraversalError("patched audit directory")

    monkeypatch.setattr(storage, "_shared_dir", refuse)
    with pytest.raises(PathTraversalError, match="^patched audit directory$"):
        storage.shared_state_modes(repo)


def test_local_state_preparation_is_read_from_storage(tmp_path, monkeypatch):
    expected = tmp_path / "prepared"
    monkeypatch.setattr(storage, "gitsafe", SimpleNamespace(common_dir=lambda root: None))
    monkeypatch.setattr(storage, "state_dir", lambda root: expected)
    assert storage.shared_state_dir(tmp_path) == expected


def test_local_confinement_receives_live_refusal_hooks(tmp_path, monkeypatch):
    calls = []
    link_error, outside_error = object(), object()
    monkeypatch.setattr(storage, "gitsafe", SimpleNamespace(common_dir=lambda root: None))
    monkeypatch.setattr(storage, "_link_error", link_error)
    monkeypatch.setattr(storage, "_outside_error", outside_error)
    monkeypatch.setattr(storage, "_confined", lambda *args, **kwargs: calls.append((args, kwargs)))
    result = storage.shared_state_dir(tmp_path, create=False)
    assert result == storage.WorkspaceLayout(tmp_path).state_dir
    assert len(calls) == 2
    assert all(args[2:] == (link_error, outside_error) for args, kwargs in calls)
    assert calls[0][1] == {"entries": False}


def test_unsupported_permission_audit_does_no_io(tmp_path, monkeypatch):
    def unexpected(root):
        pytest.fail("unsupported audit must return before Git or filesystem lookup")

    monkeypatch.setattr(storage, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(storage, "gitsafe", SimpleNamespace(common_dir=unexpected))
    assert storage.shared_state_modes(tmp_path, fix=True) == storage.StateModes(0, 0, 0, False)
    assert not (tmp_path / ".aegis").exists()


def test_state_modes_factory_is_read_from_storage(tmp_path, monkeypatch):
    calls = []
    expected = object()
    monkeypatch.setattr(storage, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(storage, "StateModes", lambda *args: calls.append(args) or expected)
    assert storage.shared_state_modes(tmp_path) is expected
    assert calls == [(0, 0, 0, False)]
