"""Public confined-file storage contract, including races and refusal cleanup."""
import os
from types import SimpleNamespace

import pytest

from aegis_core import storage


def make_store(root):
    if not storage.confined_descriptor_supported():
        pytest.skip("requires descriptor-relative nofollow operations")
    return root.resolve()


class ModuleOS(SimpleNamespace):
    def __getattr__(self, name):
        return getattr(os, name)


def test_boundary_is_loaded_only_when_its_public_api_is_used():
    from pathlib import Path
    import subprocess
    import sys
    source = ("import sys; sys.path.insert(0, sys.argv[1]); "
              "from aegis_core import storage; "
              "assert 'aegis_core.storage_confined' not in sys.modules; "
              "assert callable(storage.confined_file); "
              "assert 'aegis_core.storage_confined' in sys.modules")
    result = subprocess.run([sys.executable, "-I", "-c", source, str(Path(__file__).resolve().parents[3])],
                            capture_output=True, timeout=15)
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")


def test_read_publish_and_exclusive_creation(tmp_path):
    root = make_store(tmp_path)
    with storage.confined_file(root, ("state", "config"), create_parents=True) as handle:
        with pytest.raises(storage.ConfinedFileError) as missing:
            handle.read_bytes(8)
        assert missing.value.reason == "missing"
        handle.publish_bytes(b"original")
        assert handle.read_bytes(8) == b"original"
        with pytest.raises(storage.ConfinedFileError) as exists:
            handle.publish_bytes(b"other")
        assert exists.value.reason == "exists"
        assert handle.read_bytes(8) == b"original"
        handle.publish_bytes(b"new", replace=True, mode=0o640)
        assert handle.read_bytes(3) == b"new"
        assert handle.parent_stat().st_mode & 0o777 == 0o700
    assert (root / "state/config").stat().st_mode & 0o777 == 0o640


@pytest.mark.parametrize("parts", [(), "state/file", ("..",), (".",), ("a/b",),
                                  ("a\\b",), ("/absolute",), ("\x00secret",),
                                  ("x" * 256,), ("é" * 128,), ("\ud800",),
                                  ("x",) * 129, (None,)])
def test_invalid_components_refuse_without_echo(tmp_path, parts):
    with pytest.raises(storage.ConfinedFileError) as refused:
        with storage.confined_file(tmp_path, parts):
            pytest.fail("invalid path admitted")
    assert refused.value.reason == "invalid_path"
    assert str(refused.value) == "invalid confined file path"


def test_unsupported_platform_refuses_without_io(tmp_path, monkeypatch):
    from aegis_core import storage_confined
    monkeypatch.setattr(storage_confined, "descriptor_supported", lambda: False)
    monkeypatch.setattr(storage_confined, "os", ModuleOS(open=lambda *a, **k: pytest.fail("opened")))
    with pytest.raises(storage.ConfinedFileError) as refused:
        with storage.confined_file(tmp_path, ("file",)):
            pytest.fail("unsupported platform admitted")
    assert refused.value.reason == "unsupported"


@pytest.mark.parametrize("limit", [-1, True, 1.5, "10"])
def test_invalid_read_bound_refuses_before_open(tmp_path, monkeypatch, limit):
    from aegis_core import storage_confined
    root = make_store(tmp_path)
    with storage.confined_file(root, ("file",)) as handle:
        monkeypatch.setattr(storage_confined, "os", ModuleOS(open=lambda *a, **k: pytest.fail("opened")))
        with pytest.raises(storage.ConfinedFileError) as refused:
            handle.read_bytes(limit)
    assert refused.value.reason == "invalid_limit"


def test_size_checked_before_read_and_growth_bounded(tmp_path, monkeypatch):
    from aegis_core import storage_confined
    root = make_store(tmp_path)
    target = root / "file"
    target.write_bytes(b"12345")
    with storage.confined_file(root, ("file",)) as handle:
        monkeypatch.setattr(storage_confined, "os", ModuleOS(read=lambda *a: pytest.fail("read oversized file")))
        with pytest.raises(storage.ConfinedFileError) as refused:
            handle.read_bytes(4)
        assert refused.value.reason == "too_large"
        target.write_bytes(b"1234")
        calls = []

        def growing(fd, count):
            calls.append(count)
            return b"x" * count

        monkeypatch.setattr(storage_confined, "os", ModuleOS(read=growing))
        with pytest.raises(storage.ConfinedFileError) as refused:
            handle.read_bytes(4)
        assert refused.value.reason == "too_large" and calls == [5]


@pytest.mark.parametrize("component", [0, 1, 2])
@pytest.mark.parametrize("operation", ["read", "exclusive", "replace"])
def test_symlinks_at_every_component_refuse(tmp_path, component, operation):
    from conftest import symlink_or_skip
    root = make_store(tmp_path / "root")
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret").write_bytes(b"keep")
    parts = ("one", "two", "file")
    parent = root.joinpath(*parts[:component])
    parent.mkdir(parents=True, exist_ok=True)
    symlink_or_skip(outside if component < 2 else outside / "secret",
                    parent / parts[component], target_is_directory=component < 2)
    with pytest.raises(storage.ConfinedFileError) as refused:
        with storage.confined_file(root, parts, create_parents=True) as handle:
            if operation == "read":
                handle.read_bytes(100)
            else:
                handle.publish_bytes(b"bad", replace=operation == "replace")
    assert refused.value.reason == "unsafe"
    assert (outside / "secret").read_bytes() == b"keep"
    assert sorted(p.name for p in outside.iterdir()) == ["secret"]


@pytest.mark.parametrize("operation", ["read", "exclusive", "replace"])
def test_held_parent_survives_ancestor_rename(tmp_path, operation):
    from conftest import symlink_or_skip
    root = make_store(tmp_path / "root")
    root.mkdir()
    parent = root / "one/two"
    parent.mkdir(parents=True)
    if operation != "exclusive":
        (parent / "file").write_bytes(b"old")
    outside = tmp_path / "outside"
    outside.mkdir()
    with storage.confined_file(root, ("one", "two", "file")) as handle:
        (root / "one").rename(root / "moved")
        symlink_or_skip(outside, root / "one", target_is_directory=True)
        if operation == "read":
            assert handle.read_bytes(3) == b"old"
        else:
            handle.publish_bytes(b"new", replace=operation == "replace")
    assert not list(outside.iterdir())
    assert (root / "moved/two/file").read_bytes() == (b"old" if operation == "read" else b"new")


@pytest.mark.parametrize("failure", ["read", "write", "fstat", "fchmod", "fsync", "link", "replace"])
def test_failures_close_every_descriptor_and_remove_temporary(tmp_path, monkeypatch, failure):
    from aegis_core import storage_confined
    root = make_store(tmp_path)
    (root / "file").write_bytes(b"old")
    live = set()

    def opened(*args, **kwargs):
        fd = os.open(*args, **kwargs)
        live.add(fd)
        return fd

    def closed(fd):
        live.remove(fd)
        os.close(fd)

    def failed(*args, **kwargs):
        raise OSError("token=secret\nuntrusted")

    monkeypatch.setattr(storage_confined, "os", ModuleOS(open=opened, close=closed, **{failure: failed}))
    with pytest.raises(storage.ConfinedFileError) as refused:
        with storage.confined_file(root, ("file",)) as handle:
            if failure in ("read", "fstat"):
                handle.read_bytes(3)
            else:
                if failure == "link":
                    (root / "file").unlink()
                handle.publish_bytes(b"new", replace=failure != "link")
    assert refused.value.reason == ("durability" if failure == "fsync" else "io")
    assert str(refused.value) == ("confined file durability flush failed" if failure == "fsync"
                                  else "confined file I/O failed")
    assert not live
    assert sorted(p.name for p in root.iterdir()) == ([] if failure == "link" else ["file"])


def test_nonregular_file_refuses_without_blocking(tmp_path):
    root = make_store(tmp_path)
    os.mkfifo(root / "fifo")
    with storage.confined_file(root, ("fifo",)) as handle:
        with pytest.raises(storage.ConfinedFileError) as refused:
            handle.read_bytes(10)
        assert refused.value.reason == "unsafe"


def test_handle_refuses_after_context_exit(tmp_path):
    root = make_store(tmp_path)
    with storage.confined_file(root, ("file",)) as handle:
        handle.publish_bytes(b"ok")
    for operation in (lambda: handle.read_bytes(2), lambda: handle.publish_bytes(b"bad")):
        with pytest.raises(storage.ConfinedFileError) as refused:
            operation()
        assert refused.value.reason == "closed"


@pytest.mark.parametrize("root_name", ["relative", "../escape"])
def test_untrusted_roots_refuse(tmp_path, root_name):
    make_store(tmp_path)
    with pytest.raises(storage.ConfinedFileError) as refused:
        with storage.confined_file(root_name, ("file",), create_parents=True):
            pytest.fail("invalid root admitted")
    assert refused.value.reason == "invalid_path"


def test_missing_roots_are_not_created(tmp_path):
    root = make_store(tmp_path / "missing")
    with pytest.raises(storage.ConfinedFileError) as refused:
        with storage.confined_file(root, ("state", "file"), create_parents=True):
            pytest.fail("missing root admitted")
    assert refused.value.reason == "missing" and not root.exists()


@pytest.mark.parametrize("root_name", ["/" + "x" * 32768, "/\ud800", b"/bytes"],
                         ids=["oversize", "invalid-unicode", "bytes"])
def test_invalid_root_spellings_refuse_before_open(tmp_path, monkeypatch, root_name):
    from aegis_core import storage_confined
    make_store(tmp_path)
    monkeypatch.setattr(storage_confined, "os", ModuleOS(open=lambda *a, **k: pytest.fail("opened")))
    with pytest.raises(storage.ConfinedFileError) as refused:
        with storage.confined_file(root_name, ("file",)):
            pytest.fail("invalid root admitted")
    assert refused.value.reason == "invalid_path"


@pytest.mark.parametrize("argument,value,reason", [("data", bytearray(b"bad"), "invalid_data"),
    ("mode", -1, "invalid_mode"), ("mode", 0o1000, "invalid_mode"), ("mode", True, "invalid_mode")])
def test_invalid_publication_refuses_before_mutation(tmp_path, monkeypatch, argument, value, reason):
    from aegis_core import storage_confined
    root = make_store(tmp_path)
    with storage.confined_file(root, ("file",)) as handle:
        monkeypatch.setattr(storage_confined, "os", ModuleOS(open=lambda *a, **k: pytest.fail("opened")))
        kwargs = {"data": b"ok", argument: value}
        with pytest.raises(storage.ConfinedFileError) as refused:
            handle.publish_bytes(**kwargs)
    assert refused.value.reason == reason and not list(root.iterdir())


def test_zero_progress_write_refuses_and_cleans_temporary(tmp_path, monkeypatch):
    from aegis_core import storage_confined
    root = make_store(tmp_path)
    monkeypatch.setattr(storage_confined, "os", ModuleOS(write=lambda *a: 0))
    with storage.confined_file(root, ("file",)) as handle:
        with pytest.raises(storage.ConfinedFileError) as refused:
            handle.publish_bytes(b"ok")
    assert refused.value.reason == "io" and not list(root.iterdir())


def test_temporary_collision_preserves_the_unowned_file(tmp_path, monkeypatch):
    from aegis_core import storage_confined
    root = make_store(tmp_path)
    collision = root / ".confined-collision"
    collision.write_bytes(b"keep")
    monkeypatch.setattr(storage_confined, "uuid", SimpleNamespace(uuid4=lambda: SimpleNamespace(hex="collision")))
    with storage.confined_file(root, ("file",)) as handle:
        with pytest.raises(storage.ConfinedFileError) as refused:
            handle.publish_bytes(b"bad")
    assert refused.value.reason == "exists"
    assert collision.read_bytes() == b"keep" and not (root / "file").exists()


def test_concurrent_exclusive_publish_has_one_winner(tmp_path, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    from aegis_core import storage_confined
    root = make_store(tmp_path)
    barrier = Barrier(2, timeout=5)

    def linked(*args, **kwargs):
        barrier.wait()
        return os.link(*args, **kwargs)

    def publish(data):
        with storage.confined_file(root, ("file",)) as handle:
            try:
                handle.publish_bytes(data)
                return "published", data
            except storage.ConfinedFileError as error:
                return error.reason, data

    monkeypatch.setattr(storage_confined, "os", ModuleOS(link=linked))
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(publish, data) for data in (b"first", b"second")]
        outcomes = [future.result(timeout=10) for future in futures]
    assert sorted(reason for reason, _ in outcomes) == ["exists", "published"]
    assert (root / "file").read_bytes() == next(data for reason, data in outcomes if reason == "published")
    assert sorted(p.name for p in root.iterdir()) == ["file"]


def test_leaf_swap_during_publication_cannot_write_outside(tmp_path, monkeypatch):
    from conftest import symlink_or_skip
    from aegis_core import storage_confined
    root = make_store(tmp_path / "root")
    root.mkdir()
    outside = tmp_path / "outside"
    outside.write_bytes(b"keep")
    target = root / "file"
    target.write_bytes(b"old")

    def replaced(*args, **kwargs):
        target.unlink()
        symlink_or_skip(outside, target)
        return os.replace(*args, **kwargs)

    monkeypatch.setattr(storage_confined, "os", ModuleOS(replace=replaced))
    with storage.confined_file(root, ("file",)) as handle:
        handle.publish_bytes(b"new", replace=True)
    assert outside.read_bytes() == b"keep" and target.read_bytes() == b"new"
    assert not target.is_symlink()


class DurabilityOS(ModuleOS):
    """Observe real boundary calls and inject a failure at one named flush."""

    def __init__(self, root, fail_flush=None):
        super().__init__()
        self.root = root
        self.fail_flush = fail_flush
        self.events = []
        self.live = {}

    def open(self, path, flags, *args, **kwargs):
        fd = os.open(path, flags, *args, **kwargs)
        spelling = os.fspath(path)
        self.live[fd] = ("root" if spelling == self.root.name else
                         "temporary" if spelling.startswith(".confined-") else spelling)
        return fd

    def close(self, fd):
        self.events.append(("close", self.live.pop(fd)))
        os.close(fd)

    def mkdir(self, path, mode, *, dir_fd):
        self.events.append(("mkdir", path, self.live[dir_fd]))
        return os.mkdir(path, mode, dir_fd=dir_fd)

    def write(self, fd, data):
        self.events.append(("write", self.live[fd]))
        return os.write(fd, data)

    def fsync(self, fd):
        label = self.live[fd]
        self.events.append(("fsync", label))
        if label == self.fail_flush:
            raise OSError("token=secret\nuntrusted flush failure")
        return os.fsync(fd)

    def link(self, source, destination, **kwargs):
        self.events.append(("link", "temporary", destination))
        return os.link(source, destination, **kwargs)

    def replace(self, source, destination, **kwargs):
        self.events.append(("replace", "temporary", destination))
        return os.replace(source, destination, **kwargs)

    def unlink(self, path, **kwargs):
        self.events.append(("unlink", "temporary"))
        return os.unlink(path, **kwargs)


@pytest.mark.parametrize("replace", [False, True])
def test_publication_flushes_every_created_entry_in_order(tmp_path, monkeypatch, replace):
    from aegis_core import storage_confined
    root = make_store(tmp_path / "trusted-root")
    root.mkdir()
    proxy = DurabilityOS(root)
    monkeypatch.setattr(storage_confined, "os", proxy)
    with storage.confined_file(root, ("one", "two", "file"), create_parents=True) as handle:
        handle.publish_bytes(b"new", replace=replace)
    events = [event for event in proxy.events if event[0] != "close"]
    assert events == [
        ("mkdir", "one", "root"), ("fsync", "root"),
        ("mkdir", "two", "one"), ("fsync", "one"),
        ("write", "temporary"), ("fsync", "temporary"),
        ("replace" if replace else "link", "temporary", "file"),
        ("unlink", "temporary"), ("fsync", "two"),
    ]
    for directory in ("root", "one", "two"):
        assert proxy.events.index(("fsync", directory)) < proxy.events.index(("close", directory))
    assert not proxy.live
    assert (root / "one/two/file").read_bytes() == b"new"
    assert sorted(p.name for p in (root / "one/two").iterdir()) == ["file"]


@pytest.mark.parametrize("replace", [False, True])
@pytest.mark.parametrize("fail_flush", ["root", "one", "temporary", "two"])
def test_each_durability_failure_refuses_and_cleans(tmp_path, monkeypatch, replace, fail_flush):
    from aegis_core import storage_confined
    root = make_store(tmp_path / "trusted-root")
    root.mkdir()
    proxy = DurabilityOS(root, fail_flush=fail_flush)
    monkeypatch.setattr(storage_confined, "os", proxy)
    with pytest.raises(storage.ConfinedFileError) as refused:
        with storage.confined_file(root, ("one", "two", "file"), create_parents=True) as handle:
            handle.publish_bytes(b"new", replace=replace)
    assert refused.value.reason == "durability"
    assert refused.value.code == "CONFINED_DURABILITY"
    assert str(refused.value) == "confined file durability flush failed"
    assert not proxy.live
    flushes = [event[1] for event in proxy.events if event[0] == "fsync"]
    expected = ["root", "one", "temporary", "two"]
    assert flushes == expected[:expected.index(fail_flush) + 1]
    parent = root / "one/two"
    if parent.exists():
        assert not any(p.name.startswith(".confined-") for p in parent.iterdir())
    if fail_flush == "two":
        assert (parent / "file").read_bytes() == b"new"
    else:
        assert not (parent / "file").exists()


def assert_publication_flushes(proxy, directories, replace, name):
    assert [event[1] for event in proxy.events if event[0] == "fsync"] == [
        *directories[:-1], "temporary", directories[-1],
    ]
    publication = ("replace" if replace else "link", "temporary", name)
    for directory in directories[:-1]:
        flushed = proxy.events.index(("fsync", directory))
        assert flushed < proxy.events.index(publication)
        assert flushed < proxy.events.index(("close", directory))
    assert not proxy.live


@pytest.mark.parametrize("replace", [False, True])
@pytest.mark.parametrize("fail_flush", ["root", "one", "two"])
def test_retry_flushes_reused_ancestor_containers(tmp_path, monkeypatch, replace, fail_flush):
    from aegis_core import storage_confined
    root = make_store(tmp_path / "trusted-root")
    root.mkdir()
    parts = ("one", "two", "three", "file")
    proxy = DurabilityOS(root, fail_flush=fail_flush)
    monkeypatch.setattr(storage_confined, "os", proxy)
    with pytest.raises(storage.ConfinedFileError) as refused:
        with storage.confined_file(root, parts, create_parents=True) as handle:
            handle.publish_bytes(b"new", replace=replace)
    assert refused.value.reason == "durability"
    assert refused.value.code == "CONFINED_DURABILITY"
    assert str(refused.value) == "confined file durability flush failed"
    assert not proxy.live and not root.joinpath(*parts).exists()
    failed_depth = ("root", "one", "two").index(fail_flush)
    assert root.joinpath(*parts[:failed_depth + 1]).is_dir()

    proxy.fail_flush = None
    proxy.events.clear()
    with storage.confined_file(root, parts, create_parents=True) as handle:
        handle.publish_bytes(b"new", replace=replace)
    assert_publication_flushes(proxy, ("root", "one", "two", "three"), replace, "file")
    assert root.joinpath(*parts).read_bytes() == b"new"
    assert sorted(path.name for path in root.joinpath(*parts[:-1]).iterdir()) == ["file"]


@pytest.mark.parametrize("replace", [False, True])
@pytest.mark.parametrize("racing_component", ["one", "two", "three"])
def test_concurrent_creator_entries_are_flushed(tmp_path, monkeypatch, replace, racing_component):
    from aegis_core import storage_confined
    root = make_store(tmp_path / "trusted-root")
    root.mkdir()
    proxy = DurabilityOS(root)
    original_mkdir = proxy.mkdir
    appeared = []

    def mkdir(path, mode, *, dir_fd):
        if path == racing_component:
            # Interleave another caller's creation before our mkdir observes it;
            # that caller has not yet flushed the containing directory.
            os.mkdir(path, mode, dir_fd=dir_fd)
            appeared.append(path)
        return original_mkdir(path, mode, dir_fd=dir_fd)

    monkeypatch.setattr(proxy, "mkdir", mkdir)
    monkeypatch.setattr(storage_confined, "os", proxy)
    with storage.confined_file(root, ("one", "two", "three", "file"), create_parents=True) as handle:
        handle.publish_bytes(b"new", replace=replace)
    assert appeared == [racing_component]
    assert_publication_flushes(proxy, ("root", "one", "two", "three"), replace, "file")
    assert (root / "one/two/three/file").read_bytes() == b"new"


@pytest.mark.parametrize("force", [False, True])
@pytest.mark.parametrize("failed_depth", [0, 1])
def test_profile_retry_flushes_reused_ancestor_containers(tmp_path, monkeypatch, force, failed_depth):
    import json
    from aegis_core import storage_confined, team_profile as profile
    root = make_store(tmp_path / "trusted-root")
    root.mkdir()
    directories = ("root", *profile.REPO_PATH[:-1])
    proxy = DurabilityOS(root, fail_flush=directories[failed_depth])
    monkeypatch.setattr(storage_confined, "os", proxy)
    with pytest.raises(profile.ProfileError) as refused:
        profile.initialize(root, "solo", force=force)
    assert str(refused.value) == "unsafe or unreadable profile path"
    assert refused.value.exit_code == 1 and refused.value.layer == "repo"
    assert refused.value.file == str(root.joinpath(*profile.REPO_PATH))
    assert not proxy.live and not root.joinpath(*profile.REPO_PATH).exists()
    assert root.joinpath(*profile.REPO_PATH[:failed_depth + 1]).is_dir()

    proxy.fail_flush = None
    proxy.events.clear()
    document = profile.initialize(root, "solo", force=force)
    assert_publication_flushes(proxy, directories, force, profile.REPO_PATH[-1])
    assert json.loads(root.joinpath(*profile.REPO_PATH).read_bytes()) == document
    assert sorted(path.name for path in root.joinpath(*profile.REPO_PATH[:-1]).iterdir()) == [profile.REPO_PATH[-1]]
