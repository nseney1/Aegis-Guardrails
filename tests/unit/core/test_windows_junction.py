"""Directory junction behavior at the documented Win32 operating-system boundary."""
from __future__ import annotations

import ctypes
import os
from pathlib import Path
import stat
import struct
import sys
from types import SimpleNamespace

import pytest


class NativeFunction:
    def __init__(self, function):
        self.function = function

    def __call__(self, *args):
        return self.function(*args)


class JunctionKernel:
    def __init__(self):
        self.calls, self.links, self.buffers = [], {}, []
        self.targets = {}
        self.failure = None
        self.filesystem = "NTFS"
        self.identity_override = None
        self.stat_version = sys.version_info[:2]
        self.CreateFileW = NativeFunction(self.open)
        self.DeviceIoControl = NativeFunction(self.set_reparse)
        self.CloseHandle = NativeFunction(self.close)
        self.GetLastError = NativeFunction(lambda: 5)
        self.GetFileInformationByHandleEx = NativeFunction(self.identity)
        self.GetFileInformationByHandle = NativeFunction(self.legacy_identity)
        self.GetVolumeInformationByHandleW = NativeFunction(self.volume)

    def open(self, path, access, share, security, disposition, flags, template):
        self.calls.append(("open", path, access, share, disposition, flags))
        self.path = Path(path)
        self.opened_info = self.path.lstat()
        return ctypes.c_void_p(-1).value if self.failure == "open" else 123

    def identity(self, handle, information_class, output, size):
        self.calls.append(("identity", handle, information_class, size))
        if self.failure == "identity":
            return 0
        device, inode = self.identity_override or (self.opened_info.st_dev, self.opened_info.st_ino)
        raw = struct.pack("<Q", device) + inode.to_bytes(16, "little")
        ctypes.memmove(output, raw, len(raw))
        return 1

    def legacy_identity(self, handle, output):
        self.calls.append(("legacy_identity", handle))
        if self.failure == "legacy_identity":
            return 0
        device, inode = self.identity_override or (self.opened_info.st_dev, self.opened_info.st_ino)
        raw = struct.pack("<13L", 0x10, 0, 0, 0, 0, 0, 0, device, 0, 0, 1, inode >> 32, inode & 0xffffffff)
        ctypes.memmove(output, raw, len(raw))
        return 1

    def volume(self, handle, label, label_size, serial, maximum, flags, filesystem, size):
        self.calls.append(("volume", handle, size))
        if self.failure == "volume":
            return 0
        filesystem.value = self.filesystem
        return 1

    def set_reparse(self, handle, control, buffer, size, output, output_size, returned, overlapped):
        self.calls.append(("set", handle, control, size))
        self.buffers.append(ctypes.string_at(buffer, size))
        if self.failure == "set":
            return 0
        info = self.path.lstat()
        self.links[str(self.path)] = (info.st_dev, info.st_ino)
        raw = self.buffers[-1]
        _, _, _, _, _, offset, length = struct.unpack("<LHHHHHH", raw[:16])
        self.targets[str(self.path)] = raw[16 + offset:16 + offset + length].decode("utf-16-le")
        return 1

    def close(self, handle):
        self.calls.append(("close", handle))
        return 0 if self.failure == "close" else 1


@pytest.fixture
def junction_kernel(monkeypatch):
    kernel = JunctionKernel()
    monkeypatch.setattr(ctypes, "WinDLL", lambda name, **kwargs: kernel, raising=False)
    original, readlink, identities = Path.lstat, os.readlink, {}

    def lstat(path):
        info = original(path)
        if stat.S_ISDIR(info.st_mode):
            # Model the selected Python's stat layout independently of the host.
            # Stable real-entry keys preserve replacement/race distinctions.
            key = (info.st_dev, info.st_ino)
            ordinal = identities.setdefault(key, len(identities) + 1)
            device, inode = ((17, (1 << 40) + ordinal) if kernel.stat_version < (3, 12)
                             else ((1 << 48) + 17, (1 << 96) + ordinal))
            fields = {name: getattr(info, name) for name in dir(info) if name.startswith("st_")}
            info = SimpleNamespace(**(fields | {"st_dev": device, "st_ino": inode}))
        if kernel.links.get(str(path)) == (info.st_dev, info.st_ino):
            fields = {name: getattr(info, name) for name in dir(info) if name.startswith("st_")}
            return SimpleNamespace(**(fields | {"st_reparse_tag": 0xA0000003}))
        return info

    monkeypatch.setattr(Path, "lstat", lstat)
    monkeypatch.setattr(os, "readlink", lambda path, *args, **kwargs:
        kernel.targets[str(path)] if str(path) in kernel.targets else readlink(path, *args, **kwargs))
    return kernel


def test_junction_sends_mount_point_utf16_offsets_and_closes_its_handle(tmp_path, junction_kernel):
    from aegis_core.verification.windows_junction import create_directory_junction

    target, link = tmp_path / "dependency café 😀", tmp_path / "node_modules"
    target.mkdir()
    create_directory_junction(target, link)
    raw, = junction_kernel.buffers
    tag, length, reserved, sub_offset, sub_size, print_offset, print_size = struct.unpack("<LHHHHHH", raw[:16])
    path = str(target.resolve()).replace("/", "\\")
    assert tag == 0xA0000003 and length == len(raw) - 8 and reserved == 0
    assert sub_offset == 0 and print_offset == sub_size + 2
    assert raw[16:16 + sub_size].decode("utf-16-le") == "\\??\\" + path
    assert raw[16 + print_offset:16 + print_offset + print_size].decode("utf-16-le") == path
    assert raw[16 + sub_size:16 + print_offset] == raw[-2:] == b"\0\0"
    opened, operation, closed = [call for call in junction_kernel.calls if call[0] in {"open", "set", "close"}]
    assert opened[2:] == (0x40000080, 3, 3, 0x02200000)
    assert operation == ("set", 123, 0x000900A4, len(raw)) and closed == ("close", 123)
    assert link.lstat().st_reparse_tag == 0xA0000003


@pytest.mark.parametrize("version", [(3, 9), (3, 12)])
def test_identity_fixture_models_python_widths_when_host_identifiers_are_wide(tmp_path, monkeypatch, request, version):
    from aegis_core.verification import windows_junction

    original, host_identities = Path.lstat, {}

    def wide_host_lstat(path):
        info = original(path)
        key = (info.st_dev, info.st_ino)
        ordinal = host_identities.setdefault(key, len(host_identities) + 1)
        fields = {name: getattr(info, name) for name in dir(info) if name.startswith("st_")}
        return SimpleNamespace(**(fields | {"st_dev": (1 << 48) + 17, "st_ino": (1 << 96) + ordinal}))

    # Install the host boundary before constructing the native-kernel fixture.
    monkeypatch.setattr(Path, "lstat", wide_host_lstat)
    kernel = request.getfixturevalue("junction_kernel")
    kernel.stat_version = version
    monkeypatch.setattr(windows_junction, "sys", SimpleNamespace(version_info=version))
    target, link = tmp_path / "dependencies", tmp_path / "node_modules"
    target.mkdir()
    (target / "keep").write_text("dependency")
    windows_junction.create_directory_junction(target, link)
    assert host_identities and link.lstat().st_reparse_tag == 0xA0000003
    device, inode = kernel.opened_info.st_dev, kernel.opened_info.st_ino
    if version < (3, 12):
        assert 0 < device < (1 << 32) and 0 < inode < (1 << 64)
        assert any(call[0] == "legacy_identity" for call in kernel.calls)
    else:
        assert (1 << 32) < device < (1 << 64) and (1 << 64) < inode < (1 << 128)
        assert any(call[0] == "identity" for call in kernel.calls)
    moved = tmp_path / "moved-entry"
    link.rename(moved)
    link.mkdir()
    assert (moved.lstat().st_dev, moved.lstat().st_ino) == (device, inode)
    assert (link.lstat().st_dev, link.lstat().st_ino) != (device, inode)
    link.rmdir()
    moved.rmdir()
    assert not link.exists() and (target / "keep").read_text() == "dependency"


@pytest.mark.parametrize("failure,operation,closes", [("open", "CreateFileW", 0),
    ("set", "DeviceIoControl", 1), ("close", "CloseHandle", 1)])
def test_native_failures_remove_only_the_new_empty_entry(tmp_path, junction_kernel, failure, operation, closes):
    from aegis_core.verification.windows_junction import create_directory_junction

    target, link = tmp_path / "dependencies", tmp_path / "node_modules"
    target.mkdir()
    (target / "keep").write_text("dependency")
    junction_kernel.failure = failure
    with pytest.raises(OSError, match=operation + " failed: Windows error 5"):
        create_directory_junction(target, link)
    # A failed open supplies no trustworthy handle identity for rollback.
    assert link.exists() == (failure == "open")
    assert (target / "keep").read_text() == "dependency"
    assert sum(call[0] == "close" for call in junction_kernel.calls) == closes


def test_existing_entry_is_never_replaced(tmp_path, junction_kernel):
    from aegis_core.verification.windows_junction import create_directory_junction

    target, link = tmp_path / "dependencies", tmp_path / "node_modules"
    target.mkdir()
    link.mkdir()
    (link / "keep").write_text("owner")
    with pytest.raises(FileExistsError):
        create_directory_junction(target, link)
    assert (link / "keep").read_text() == "owner" and not junction_kernel.calls


def test_failed_creation_preserves_an_entry_replaced_at_the_os_boundary(tmp_path, junction_kernel):
    from aegis_core.verification.windows_junction import create_directory_junction

    target, link = tmp_path / "dependencies", tmp_path / "node_modules"
    target.mkdir()

    def replace(*args):
        link.rename(tmp_path / "moved-entry")
        link.mkdir()
        (link / "keep").write_text("replacement")
        return 0

    junction_kernel.DeviceIoControl.function = replace
    with pytest.raises(OSError, match="DeviceIoControl failed"):
        create_directory_junction(target, link)
    assert (link / "keep").read_text() == "replacement"
    assert junction_kernel.calls[-1] == ("close", 123)


def test_successful_native_call_does_not_adopt_a_replacement_junction(tmp_path, junction_kernel):
    from aegis_core.verification.windows_junction import create_directory_junction

    target, link = tmp_path / "dependencies", tmp_path / "node_modules"
    target.mkdir()
    original = junction_kernel.DeviceIoControl.function

    def replace(*args):
        result = original(*args)
        link.rename(tmp_path / "moved-entry")
        link.mkdir()
        (link / "keep").write_text("replacement")
        info = link.lstat()
        junction_kernel.links[str(link)] = (info.st_dev, info.st_ino)
        return result

    junction_kernel.DeviceIoControl.function = replace
    with pytest.raises(OSError, match="changed during creation"):
        create_directory_junction(target, link)
    assert (link / "keep").read_text() == "replacement"
    assert junction_kernel.calls[-1] == ("close", 123)


def test_replacement_before_native_open_is_never_modified(tmp_path, junction_kernel):
    from aegis_core.verification.windows_junction import create_directory_junction

    target, link = tmp_path / "dependencies", tmp_path / "node_modules"
    target.mkdir()
    (target / "keep").write_text("dependency")
    original = junction_kernel.CreateFileW.function

    def replace(*args):
        link.rename(tmp_path / "owned-entry")
        link.mkdir()
        return original(*args)

    junction_kernel.CreateFileW.function = replace
    with pytest.raises(OSError, match="changed during creation"):
        create_directory_junction(target, link)
    assert not junction_kernel.buffers, "DeviceIoControl modified the replacement directory"
    assert getattr(link.lstat(), "st_reparse_tag", 0) != 0xA0000003
    assert link.is_dir() and (tmp_path / "owned-entry").is_dir()
    assert (target / "keep").read_text() == "dependency"
    assert junction_kernel.calls[-1] == ("close", 123)


@pytest.mark.parametrize("version", [(3, 9), (3, 12)])
@pytest.mark.parametrize("problem", ["query_failure", "volume_mismatch", "file_mismatch", "zero_identity"])
def test_handle_identity_failure_preserves_entry_without_writing(tmp_path, monkeypatch, junction_kernel, version, problem):
    from aegis_core.verification import windows_junction

    monkeypatch.setattr(windows_junction, "sys", SimpleNamespace(version_info=version), raising=False)
    junction_kernel.stat_version = version
    target, link = tmp_path / "dependencies", tmp_path / "node_modules"
    target.mkdir()
    original = junction_kernel.CreateFileW.function

    def opened(*args):
        handle = original(*args)
        info = junction_kernel.opened_info
        if problem == "query_failure":
            junction_kernel.failure = "identity" if version >= (3, 12) else "legacy_identity"
        elif problem == "volume_mismatch":
            changed = info.st_dev + (1 << 40) if version >= (3, 12) else info.st_dev + 1
            junction_kernel.identity_override = (changed, info.st_ino)
        elif problem == "zero_identity":
            junction_kernel.identity_override = (info.st_dev, 0)
        else:
            changed = info.st_ino + (1 << 80) if version >= (3, 12) else info.st_ino + 1
            junction_kernel.identity_override = (info.st_dev, changed)
        return handle

    junction_kernel.CreateFileW.function = opened
    message = {"query_failure": "GetFileInformationByHandle.*failed: Windows error 5",
               "zero_identity": "identity unavailable"}.get(problem, "changed during creation")
    with pytest.raises(OSError, match=message):
        windows_junction.create_directory_junction(target, link)
    assert link.is_dir() and not junction_kernel.buffers
    assert sum(call[0] == "close" for call in junction_kernel.calls) == 1


@pytest.mark.parametrize("filesystem", ["ReFS", "unknown", "query_failure"])
def test_legacy_ambiguous_filesystem_never_authorizes_write_or_rollback(tmp_path, monkeypatch, junction_kernel, filesystem):
    from aegis_core.verification import windows_junction

    monkeypatch.setattr(windows_junction, "sys", SimpleNamespace(version_info=(3, 9)), raising=False)
    junction_kernel.stat_version = (3, 9)
    target, link = tmp_path / "dependencies", tmp_path / "node_modules"
    target.mkdir()
    junction_kernel.filesystem = filesystem
    if filesystem == "query_failure":
        junction_kernel.failure = "volume"
    message = "GetVolumeInformationByHandleW failed: Windows error 5" if filesystem == "query_failure" else "requires NTFS"
    with pytest.raises(OSError, match=message):
        windows_junction.create_directory_junction(target, link)
    assert link.is_dir() and not junction_kernel.buffers
    assert sum(call[0] == "close" for call in junction_kernel.calls) == 1


@pytest.mark.parametrize("version", [(3, 9), (3, 12)])
def test_matching_native_identity_is_verified_before_the_write(tmp_path, monkeypatch, junction_kernel, version):
    from aegis_core.verification import windows_junction

    monkeypatch.setattr(windows_junction, "sys", SimpleNamespace(version_info=version), raising=False)
    junction_kernel.stat_version = version
    target, link = tmp_path / "dependencies", tmp_path / "node_modules"
    target.mkdir()
    windows_junction.create_directory_junction(target, link)
    names = [call[0] for call in junction_kernel.calls]
    identity = "identity" if version >= (3, 12) else "legacy_identity"
    assert identity in names and names.index(identity) < names.index("set")
    assert names.count("close") == 1 and names[-1] == "close"
    if version >= (3, 12):
        assert ("identity", 123, 18, 24) in junction_kernel.calls
    else:
        assert names.index("volume") < names.index("legacy_identity")


@pytest.mark.parametrize("kind", ["missing", "file"])
def test_missing_or_nondirectory_target_is_refused(tmp_path, junction_kernel, kind):
    from aegis_core.verification.windows_junction import create_directory_junction

    target, link = tmp_path / "dependencies", tmp_path / "node_modules"
    if kind == "file":
        target.write_text("not a directory")
    with pytest.raises(NotADirectoryError):
        create_directory_junction(target, link)
    assert not link.exists() and not junction_kernel.calls


@pytest.mark.parametrize("resolved,message", [
    ("\\\\server\\share\\node_modules", "local target"),
    ("\\\\?\\unc\\server\\share\\node_modules", "local target"),
    ("C:\\" + "x" * 8192, "reparse buffer limit"),
])
def test_unsupported_resolved_targets_fail_before_creating_an_entry(tmp_path, monkeypatch, junction_kernel, resolved, message):
    from aegis_core.verification.windows_junction import create_directory_junction

    target, link = tmp_path / "dependencies", tmp_path / "node_modules"
    target.mkdir()
    original = Path.resolve
    monkeypatch.setattr(Path, "resolve", lambda path, *args, **kwargs:
        Path(resolved) if path == target else original(path, *args, **kwargs))
    with pytest.raises(OSError, match=message):
        create_directory_junction(target, link)
    assert not link.exists() and not junction_kernel.calls


def test_success_status_without_mount_point_tag_is_not_accepted(tmp_path, junction_kernel):
    from aegis_core.verification.windows_junction import create_directory_junction

    target, link = tmp_path / "dependencies", tmp_path / "node_modules"
    target.mkdir()
    junction_kernel.DeviceIoControl.function = lambda *args: 1
    with pytest.raises(OSError, match="wrong reparse tag"):
        create_directory_junction(target, link)
    assert not link.exists() and junction_kernel.calls[-1] == ("close", 123)


@pytest.mark.skipif(os.name != "nt", reason="requires the actual Windows junction filesystem")
@pytest.mark.parametrize("dangling", [False, True])
def test_real_windows_junction_reads_target_without_symlink_privilege_and_removes_only_link(tmp_path, monkeypatch, dangling):
    from aegis_core.verification.windows_junction import create_directory_junction

    def denied(*args, **kwargs):
        raise PermissionError("symlink creation is deliberately disabled")

    monkeypatch.setattr(Path, "symlink_to", denied)
    target, link = tmp_path / "dependency café 😀", tmp_path / "node_modules"
    target.mkdir()
    (target / "keep").write_text("dependency")
    create_directory_junction(target, link)
    try:
        assert link.lstat().st_reparse_tag == 0xA0000003 and not link.is_symlink()
        assert (link / "keep").read_text() == "dependency"
        if dangling:
            target.rename(tmp_path / "moved-dependencies")
            assert os.path.lexists(link) and not link.exists()
    finally:
        link.rmdir()
    retained = tmp_path / "moved-dependencies" if dangling else target
    assert not link.exists() and (retained / "keep").read_text() == "dependency"
