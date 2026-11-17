"""aegis_core.pathlookup: the one lookup of a program on PATH (host-matrix §3.7).

Aegis starts what this finds (a host CLI, python3) and writes the aegis-mcp it finds
into a host's config, from inside a repository the user may just have cloned. So only
absolute PATH entries count: an empty or relative entry names the current directory,
where the repository can plant a program. An absolute entry inside a fence (the
workspace, for doctor) does not count either. ``only_skipped`` reports where a program
is reachable when every one of those places was refused, so a caller never reports a
host it passed over as plainly absent.
"""
from __future__ import annotations

import contextlib
import os
import stat
import sys
from pathlib import Path

import pytest

from aegis_core.pathlookup import Hit, only_skipped, which

EXE = ".exe" if os.name == "nt" else ""


def _program(directory: Path, name: str, data: bytes = b"#!/bin/sh\nexit 0\n") -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / (name + EXE)
    path.write_bytes(data)
    path.chmod(0o755)
    return path


def _path(*entries) -> str:
    return os.pathsep.join(str(e) for e in entries)


# ── which ────────────────────────────────────────────────────────────────────

def test_the_first_absolute_entry_holding_the_program_wins(tmp_path):
    first = _program(tmp_path / "a", "codex")
    _program(tmp_path / "b", "codex")
    assert which("codex", _path(tmp_path / "empty", tmp_path / "a", tmp_path / "b")) == str(first)


def test_a_name_on_no_entry_is_none(tmp_path):
    (tmp_path / "empty").mkdir()
    assert which("codex", _path(tmp_path / "empty")) is None
    assert which("codex", "") is None


@pytest.mark.parametrize("entry", ["", ".", "bin", os.path.join(".", "bin")])
def test_empty_and_relative_entries_are_never_searched(tmp_path, monkeypatch, entry):
    # Each names a directory relative to the cwd, where a repository plants programs.
    _program(tmp_path, "codex")
    _program(tmp_path / "bin", "codex")
    monkeypatch.chdir(tmp_path)
    assert which("codex", _path(entry)) is None
    real = _program(tmp_path / "real", "codex")
    assert which("codex", _path(entry, real.parent)) == str(real)


def test_the_default_path_is_the_environment_path(tmp_path, monkeypatch):
    exe = _program(tmp_path / "bin", "aegis-mcp")
    monkeypatch.setenv("PATH", str(exe.parent))
    assert which("aegis-mcp") == str(exe)


def test_an_entry_inside_the_fence_is_skipped_and_the_next_one_wins(tmp_path):
    ws = tmp_path / "ws"
    _program(ws / "tools", "codex")
    real = _program(tmp_path / "bin", "codex")
    path = _path(ws / "tools", real.parent)
    assert which("codex", path, outside=ws) == str(real)
    assert which("codex", _path(ws / "tools"), outside=ws) is None
    assert which("codex", _path(ws / "tools")) == str(ws / "tools" / ("codex" + EXE))


def test_the_fence_itself_is_inside_the_fence(tmp_path):
    ws = tmp_path / "ws"
    _program(ws, "codex")
    assert which("codex", _path(ws), outside=ws) is None


def test_a_sibling_sharing_the_fence_prefix_is_outside_it(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    sibling = _program(tmp_path / "ws-tools", "codex")
    assert which("codex", _path(sibling.parent), outside=ws) == str(sibling)


def test_a_linked_entry_into_the_fence_is_inside_it(tmp_path):
    ws = tmp_path / "ws"
    _program(ws / "bin", "codex")
    link = tmp_path / "linkbin"
    try:
        link.symlink_to(ws / "bin", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available")
    assert which("codex", _path(link), outside=ws) is None


def test_a_linked_program_is_returned_under_its_own_name(tmp_path):
    # Version managers dispatch on argv[0]: the name found on PATH is what runs.
    real = _program(tmp_path / "toolchain", "dispatcher")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    try:
        (bindir / ("codex" + EXE)).symlink_to(real)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available")
    assert which("codex", _path(bindir)) == str(bindir / ("codex" + EXE))


@pytest.mark.skipif(os.name == "nt", reason="Windows has no execute bit")
def test_a_file_without_the_execute_bit_is_not_a_program(tmp_path):
    exe = _program(tmp_path / "bin", "codex")
    exe.chmod(0o644)
    assert which("codex", _path(exe.parent)) is None


def test_a_directory_named_like_the_program_is_not_a_program(tmp_path):
    (tmp_path / "bin" / ("codex" + EXE)).mkdir(parents=True)
    assert which("codex", _path(tmp_path / "bin")) is None


class TestWindowsLookup:
    """PATHEXT candidates matched case-insensitively against the directory, returned
    in the file's own spelling. Emulated off Windows by the platform name."""

    @pytest.fixture
    def windows(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "win32")
        monkeypatch.setenv("PATHEXT", os.pathsep.join([".COM", ".EXE", ".BAT", ".CMD"]))

    @pytest.mark.parametrize("on_disk", ["codex.exe", "codex.Exe", "CODEX.EXE"])
    def test_the_on_disk_spelling_is_returned(self, tmp_path, windows, on_disk):
        exe = tmp_path / "bin" / on_disk
        exe.parent.mkdir()
        exe.write_bytes(b"MZ")
        exe.chmod(0o755)
        assert which("codex", str(exe.parent)) == str(exe)

    def test_a_cmd_shim_is_found_after_the_exe_extensions(self, tmp_path, windows):
        shim = tmp_path / "npm" / "codex.cmd"
        shim.parent.mkdir()
        shim.write_bytes(b"@echo off\r\n")
        shim.chmod(0o755)
        assert which("codex", str(shim.parent)) == str(shim)

    def test_a_name_that_carries_an_extension_is_looked_up_as_given(self, tmp_path, windows):
        exe = tmp_path / "bin" / "python3.exe"
        exe.parent.mkdir()
        exe.write_bytes(b"MZ")
        exe.chmod(0o755)
        assert which("python3.EXE", str(exe.parent)) == str(exe)

    def test_a_name_without_a_pathext_extension_is_not_a_program(self, tmp_path, windows):
        script = tmp_path / "bin" / "codex"
        script.parent.mkdir()
        script.write_bytes(b"#!/bin/sh\n")
        script.chmod(0o755)
        assert which("codex", str(script.parent)) is None

    def test_relative_entries_are_skipped_on_windows_too(self, tmp_path, windows, monkeypatch):
        shim = tmp_path / "codex.cmd"
        shim.write_bytes(b"@echo off\r\n")
        shim.chmod(0o755)
        monkeypatch.chdir(tmp_path)
        assert which("codex", os.pathsep.join(["", "."])) is None

    # What only_skipped reports is what doctor lists in binary.ignored: the three Windows CI
    # failures at 41cd3f0 were codex.EXE reported for a codex.exe on disk.
    @pytest.mark.parametrize("on_disk", ["codex.exe", "Codex.Exe"])
    def test_a_program_passed_over_inside_the_fence_keeps_its_on_disk_spelling(self, tmp_path, windows,
                                                                               on_disk):
        ws = tmp_path / "ws"
        exe = ws / "tools" / on_disk
        exe.parent.mkdir(parents=True)
        exe.write_bytes(b"MZ")
        exe.chmod(0o755)
        assert only_skipped("codex", str(exe.parent), outside=ws) == [
            Hit(path=str(exe), entry=str(exe.parent), reason="inside_fence")]

    @pytest.mark.parametrize("on_disk", ["codex.exe", "Codex.Exe"])
    def test_a_program_passed_over_on_a_relative_entry_keeps_its_on_disk_spelling(self, tmp_path, windows,
                                                                                  on_disk):
        ws = tmp_path / "ws"
        exe = ws / "bin" / on_disk
        exe.parent.mkdir(parents=True)
        exe.write_bytes(b"MZ")
        exe.chmod(0o755)
        assert only_skipped("codex", "bin", outside=ws, base=ws) == [
            Hit(path=os.path.normpath(str(exe)), entry="bin", reason="relative_entry")]


# ── only_skipped ─────────────────────────────────────────────────────────────

def test_only_skipped_is_empty_when_which_finds_the_program(tmp_path):
    ws = tmp_path / "ws"
    _program(ws / "bin", "codex")
    real = _program(tmp_path / "bin", "codex")
    assert only_skipped("codex", _path("bin", ws / "bin", real.parent), outside=ws, base=ws) == []


def test_only_skipped_is_empty_when_the_program_is_nowhere(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    assert only_skipped("codex", _path("", ".", "bin", ws), outside=ws, base=ws) == []


@pytest.mark.parametrize("entry, where", [("", "."), (".", "."), ("bin", "bin"),
                                          (os.path.join("..", "tools"), os.path.join("..", "tools"))])
def test_a_program_reachable_only_through_a_relative_entry_is_reported(tmp_path, entry, where):
    ws = tmp_path / "ws"
    exe = _program(ws / where, "codex")
    hits = only_skipped("codex", _path(entry), outside=ws, base=ws)
    assert hits == [Hit(path=os.path.normpath(str(exe)), entry=entry, reason="relative_entry")]


def test_a_relative_entry_resolves_against_the_cwd_by_default(tmp_path, monkeypatch):
    exe = _program(tmp_path / "bin", "codex")
    monkeypatch.chdir(tmp_path)
    assert only_skipped("codex", _path("bin")) == [
        Hit(path=os.path.normpath(os.path.join(os.getcwd(), "bin", "codex" + EXE)), entry="bin",
            reason="relative_entry")]
    assert exe.is_file()


def test_a_program_reachable_only_inside_the_fence_is_reported(tmp_path):
    ws = tmp_path / "ws"
    exe = _program(ws / "tools", "codex")
    assert only_skipped("codex", _path(ws / "tools"), outside=ws) == [
        Hit(path=str(exe), entry=str(ws / "tools"), reason="inside_fence")]


def test_every_refused_place_is_reported_once_in_path_order(tmp_path):
    ws = tmp_path / "ws"
    inside = _program(ws / "tools", "codex")
    relative = _program(ws / "bin", "codex")
    hits = only_skipped("codex", _path(ws / "tools", "bin", ws / "tools", "bin"), outside=ws, base=ws)
    assert [(h.path, h.reason) for h in hits] == [(str(inside), "inside_fence"),
                                                   (os.path.normpath(str(relative)), "relative_entry")]


def test_without_a_fence_only_relative_entries_are_refused(tmp_path):
    ws = tmp_path / "ws"
    _program(ws / "tools", "codex")
    assert only_skipped("codex", _path(ws / "tools"), base=ws) == []


def test_an_outside_program_whose_realpath_is_inside_the_fence_is_skipped(tmp_path):
    from conftest import symlink_or_skip
    ws = tmp_path / "ws"
    planted = _program(ws / "bin", "codex")
    outside = tmp_path / "outside"
    outside.mkdir()
    alias = outside / ("codex" + EXE)
    symlink_or_skip(planted, alias)
    real = _program(tmp_path / "host", "codex")
    assert which("codex", _path(outside), outside=ws) == str(alias)
    assert which("codex", _path(outside, real.parent), outside=ws, fence_program=True) == str(real)
    assert only_skipped("codex", _path(outside), outside=ws, fence_program=True) == [
        Hit(path=str(alias), entry=str(outside), reason="inside_fence")]


@pytest.mark.parametrize("fence,entry", [
    (r"C:\ws", r"C:\ws\tools"),
    (r"C:\ws", r"\\?\C:\ws\tools"),
    (r"C:\ws", r"\\.\C:\ws\tools"),
    (r"\\server\share\ws", r"\\server\share\ws\tools"),
    (r"\\server\share\ws", r"\\?\UNC\server\share\ws\tools"),
    (r"\\server\share\ws", r"\\.\UNC\server\share\ws\tools"),
], ids=["drive", "extended-drive", "device-drive", "unc", "extended-unc", "device-unc"])
def test_windows_in_fence_alias_spellings_are_refused(fence, entry):
    """Model Windows OS results so both path namespaces run on every CI host."""
    import ntpath
    from types import SimpleNamespace
    from aegis_core import pathlookup, primitives
    original, primitive_os, original_sys = pathlookup.os, primitives.os, pathlookup.sys

    def resolved(path):
        return fence if ntpath.normcase(os.fspath(path)) == ntpath.normcase(fence) else r"D:\host\git"

    paths = SimpleNamespace(**{**vars(ntpath), "realpath": resolved,
        "islink": lambda path: False, "isfile": lambda path: True})
    modeled = SimpleNamespace(**{**vars(original), "name": "nt", "sep": "\\",
        "altsep": "/", "pathsep": ";", "path": paths, "access": lambda *args: True,
        "listdir": lambda directory: ["git.exe"], "environ": {"PATHEXT": ".EXE"}})
    pathlookup.os = primitives.os = modeled
    pathlookup.sys = SimpleNamespace(**{**vars(original_sys), "platform": "win32"})
    try:
        assert pathlookup.which("git.exe", path=entry, outside=fence, fence_program=True) is None
        assert pathlookup.only_skipped("git.exe", path=entry, outside=fence, fence_program=True) == [
            Hit(path=ntpath.join(entry, "git.exe"), entry=entry, reason=pathlookup.INSIDE_FENCE)]
    finally:
        pathlookup.os, primitives.os = original, primitive_os
        pathlookup.sys = original_sys


def _outer_marker_fence(path):
    start = Path(os.path.realpath(path))
    for parent in reversed((start, *start.parents)):
        if os.path.lexists(parent / ".git"):
            return os.path.normcase(str(parent))
    return os.path.normcase(str(start))


def test_git_fence_uses_outermost_marker_across_discovery_ceilings(tmp_path):
    from aegis_core import pathlookup
    high = tmp_path / "high"
    (high / ".git").mkdir(parents=True)
    ceiling = high / "stop"
    plain = ceiling / "plain"
    plain.mkdir(parents=True)
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / ".git").write_text("gitdir: /nowhere\n", encoding="utf-8")
    (nested / "sub").mkdir()
    previous = os.environ.get("GIT_CEILING_DIRECTORIES")
    os.environ["GIT_CEILING_DIRECTORIES"] = str(ceiling)
    try:
        assert pathlookup.git_fence(plain) == _outer_marker_fence(high)
        assert pathlookup.git_fence(nested / "sub") == _outer_marker_fence(nested)
        assert pathlookup.git_fence("bad\0start") == os.path.normcase(os.path.abspath(os.sep))
        probe = pathlookup.descriptor_fence_supported
        pathlookup.descriptor_fence_supported = lambda: False
        try:
            assert pathlookup.git_fence(nested / "sub") == _outer_marker_fence(nested)
            assert pathlookup.git_fence(plain) == _outer_marker_fence(high)
        finally:
            pathlookup.descriptor_fence_supported = probe
    finally:
        if previous is None:
            os.environ.pop("GIT_CEILING_DIRECTORIES", None)
        else:
            os.environ["GIT_CEILING_DIRECTORIES"] = previous


def test_git_fence_counts_a_symlinked_marker_without_following_it(tmp_path):
    from conftest import symlink_or_skip
    from aegis_core import pathlookup
    linked = tmp_path / "linked"
    (linked / "sub").mkdir(parents=True)
    symlink_or_skip("not-a-target", linked / ".git")
    assert pathlookup.git_fence(linked / "sub") == _outer_marker_fence(linked)
    probe = pathlookup.descriptor_fence_supported
    pathlookup.descriptor_fence_supported = lambda: False
    try:
        assert pathlookup.git_fence(linked / "sub") == _outer_marker_fence(linked)
    finally:
        pathlookup.descriptor_fence_supported = probe


@pytest.mark.skipif(os.name != "posix", reason="FIFO markers need POSIX")
def test_git_fence_never_opens_a_fifo_marker(tmp_path):
    import subprocess
    from aegis_core import pathlookup
    if not pathlookup.descriptor_fence_supported():
        pytest.skip("descriptor-relative discovery is unavailable")
    ws = tmp_path / "ws"
    ws.mkdir()
    os.mkfifo(ws / ".git")
    code = "from aegis_core.pathlookup import git_fence; import sys; print(git_fence(sys.argv[1]))"
    result = subprocess.run([sys.executable, "-c", code, str(ws)],
                            capture_output=True, text=True, timeout=5, check=True)
    assert result.stdout.strip() == _outer_marker_fence(ws)


@pytest.mark.skipif(os.name != "posix", reason="backslash is a POSIX filename character")
def test_git_fence_preserves_backslashes_in_directory_names(tmp_path):
    from aegis_core import pathlookup
    if not pathlookup.descriptor_fence_supported():
        pytest.skip("descriptor-relative discovery is unavailable")
    ws = tmp_path / "ws\\name"
    (ws / ".git").mkdir(parents=True)
    sub = ws / "sub"
    sub.mkdir()
    assert pathlookup.git_fence(sub) == _outer_marker_fence(ws)


@pytest.mark.parametrize("failure", [OSError, ValueError, RuntimeError])
def test_git_fence_closes_parent_descriptor_when_location_fails(tmp_path, failure):
    from aegis_core import pathlookup
    if not pathlookup.descriptor_fence_supported() or not os.path.isdir("/proc/self/fd"):
        pytest.skip("descriptor count check needs Linux procfs")
    ws = tmp_path / "ws"
    (ws / ".git").mkdir(parents=True)
    sub = ws / "sub"
    sub.mkdir()
    original = pathlookup._fd_location
    calls = []

    def location(fd):
        calls.append(fd)
        if len(calls) == 3:
            raise failure("untrusted-location-diagnostic")
        return original(fd)

    before = len(os.listdir("/proc/self/fd"))
    pathlookup._fd_location = location
    try:
        assert pathlookup.git_fence(sub) == os.path.abspath(os.sep)
    finally:
        pathlookup._fd_location = original
    assert len(os.listdir("/proc/self/fd")) == before
    assert pathlookup.git_fence(sub) == _outer_marker_fence(ws)


def test_git_fence_refuses_a_component_replaced_by_a_symlink_during_open(tmp_path):
    from conftest import symlink_or_skip
    from aegis_core import pathlookup
    if not pathlookup.descriptor_fence_supported():
        pytest.skip("no-follow descriptor discovery is unavailable")
    outside = tmp_path / "outside"
    outside.mkdir()
    pivot = tmp_path / "pivot"
    (pivot / ".git").mkdir(parents=True)
    parked = tmp_path / "parked"
    # Qualify symlink capability before entering the deterministic replacement.
    probe = tmp_path / "probe"
    symlink_or_skip(outside, probe, target_is_directory=True)
    probe.unlink()
    original = pathlookup._open_directory
    changes = []

    def opening(parent, name):
        if name == "pivot" and not changes:
            changes.append(name)
            pivot.rename(parked)
            symlink_or_skip(outside, pivot, target_is_directory=True)
        return original(parent, name)

    pathlookup._open_directory = opening
    try:
        assert pathlookup.git_fence(pivot) == os.path.abspath(os.sep)
    finally:
        pathlookup._open_directory = original
    assert changes == ["pivot"]
    pivot.unlink()
    parked.rename(pivot)
    assert pathlookup.git_fence(pivot) == _outer_marker_fence(pivot)


def test_git_fence_falls_back_when_fd_directory_cannot_locate_descriptors(tmp_path):
    from types import SimpleNamespace
    from aegis_core import pathlookup
    if not pathlookup.descriptor_fence_supported():
        pytest.skip("models a POSIX descriptor locator")
    ws = tmp_path / "ws"
    (ws / ".git").mkdir(parents=True)
    original = pathlookup.os

    def realpath(path):
        text = os.fspath(path)
        if text.startswith("/proc/self/fd/") or text.startswith("/dev/fd/"):
            return text
        return os.path.realpath(path)

    pathlookup.os = SimpleNamespace(**{**vars(os), "path": SimpleNamespace(
        **{**vars(os.path), "realpath": realpath})})
    try:
        assert pathlookup.git_fence(ws) == _outer_marker_fence(ws)
    finally:
        pathlookup.os = original


def test_descriptor_probe_requires_nofollow_stat_support():
    from types import SimpleNamespace
    from aegis_core import pathlookup
    original = pathlookup.os
    pathlookup.os = SimpleNamespace(**{**vars(os), "supports_follow_symlinks": set()})
    try:
        assert not pathlookup.descriptor_fence_supported()
    finally:
        pathlookup.os = original


def test_git_fence_checks_component_budget_before_path_resolution():
    from types import SimpleNamespace
    from aegis_core import pathlookup
    start = os.sep + os.sep.join(["component"] * 513)
    original = pathlookup.os

    def resolve(path):
        if path == start:
            raise AssertionError("over-budget input reached path resolution")
        return os.path.realpath(path)

    pathlookup.os = SimpleNamespace(**{**vars(os), "path": SimpleNamespace(
        **{**vars(os.path), "realpath": resolve})})
    try:
        assert pathlookup.git_fence(start) == os.path.normcase(os.path.abspath(os.sep))
    finally:
        pathlookup.os = original


@pytest.mark.parametrize("root_marker", [False, True], ids=["no-markers", "filesystem-root"])
def test_git_fence_cwd_fallback_and_filesystem_root_are_explicit(tmp_path, root_marker):
    from types import SimpleNamespace
    from aegis_core import pathlookup
    original, probe = pathlookup.os, pathlookup.descriptor_fence_supported
    root = os.path.abspath(os.sep)

    def marker_stat(path, *args, **kwargs):
        if os.path.basename(path) == ".git":
            if root_marker and path == os.path.join(root, ".git"):
                return SimpleNamespace(st_mode=stat.S_IFDIR)
            raise FileNotFoundError(2, "no modeled marker")
        return os.stat(path, *args, **kwargs)

    pathlookup.os = SimpleNamespace(**{**vars(os), "stat": marker_stat, "path": SimpleNamespace(
        **{**vars(os.path), "lexists": lambda path: root_marker and path == os.path.join(root, ".git")})})
    pathlookup.descriptor_fence_supported = lambda: False
    try:
        expected = root if root_marker else os.path.realpath(tmp_path)
        assert pathlookup.git_fence(tmp_path) == os.path.normcase(expected)
    finally:
        pathlookup.os = original
        pathlookup.descriptor_fence_supported = probe


@pytest.mark.parametrize("components", [512, 513])
def test_git_fence_component_limit_includes_the_root_walk(components):
    import posixpath
    from types import SimpleNamespace
    from aegis_core import pathlookup
    original, probe = pathlookup.os, pathlookup.descriptor_fence_supported
    start = "/anchor" + "/d" * (components - 1)
    paths = SimpleNamespace(**{**vars(posixpath), "realpath": lambda path: path,
        "islink": lambda path: False, "isfile": lambda path: False,
        "lexists": lambda path: path == "/anchor/.git"})

    def directory(path, *args, **kwargs):
        return SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=0, st_reparse_tag=0)

    def marker_stat(path, *args, **kwargs):
        if path == "/anchor/.git":
            return SimpleNamespace(st_mode=stat.S_IFDIR)
        raise FileNotFoundError(2, "no modeled marker")

    pathlookup.os = SimpleNamespace(**{**vars(original), "sep": "/", "altsep": None, "path": paths,
        "lstat": directory, "stat": marker_stat})
    pathlookup.descriptor_fence_supported = lambda: False
    try:
        assert pathlookup.git_fence(start) == ("/anchor" if components == 512 else "/")
    finally:
        pathlookup.os = original
        pathlookup.descriptor_fence_supported = probe


@contextlib.contextmanager
def _metadata_walk(enabled):
    """Force the no-descriptor walk when enabled is false; leave the host probe alone otherwise."""
    from aegis_core import pathlookup
    if enabled:
        yield
        return
    probe = pathlookup.descriptor_fence_supported
    pathlookup.descriptor_fence_supported = lambda: False
    try:
        yield
    finally:
        pathlookup.descriptor_fence_supported = probe


@contextlib.contextmanager
def _observe_reparse(observer):
    """Install a no-follow reparse observer for one lookup, then restore the platform classifier."""
    from aegis_core import pathlookup
    previous = pathlookup._reparse_observer
    pathlookup._reparse_observer = observer
    try:
        yield
    finally:
        pathlookup._reparse_observer = previous


def _outside_resolved(path, fence):
    resolved, root = os.path.normcase(os.path.realpath(path)), os.path.normcase(os.path.realpath(fence))
    return resolved != root and not resolved.startswith(root.rstrip(os.sep) + os.sep)


@pytest.mark.parametrize("descriptors", [True, False], ids=["descriptors", "metadata"])
def test_a_legitimate_outside_parent_entry_is_kept(tmp_path, descriptors):
    """'..' on a walk that never enters the fence stays eligible, spelled as written."""
    ws = tmp_path / "ws"
    ws.mkdir()
    deep = tmp_path / "host" / "deep"
    deep.mkdir(parents=True)
    program = _program(tmp_path / "host" / "bin", "codex")
    entry = str(deep) + os.sep + ".." + os.sep + "bin"
    spelled = os.path.join(entry, program.name)
    with _metadata_walk(descriptors):
        assert which("codex", entry, outside=ws) == spelled
        assert which("codex", entry, outside=ws, fence_program=True) == spelled


@pytest.mark.parametrize("descriptors", [True, False], ids=["descriptors", "metadata"])
def test_outside_symlink_into_the_fence_and_back_out_is_skipped(tmp_path, descriptors):
    """A directory symlink whose target enters the fence and leaves is an inside entry."""
    from conftest import symlink_or_skip
    ws = tmp_path / "ws"
    (ws / "decoy").mkdir(parents=True)
    program = _program(tmp_path / "host" / "bin", "codex")
    outside = tmp_path / "outside"
    outside.mkdir()
    link = outside / "detour"
    target = os.path.join(str(ws / "decoy"), "..", "..", "host", "bin")
    symlink_or_skip(target, link, target_is_directory=True)
    real = _program(tmp_path / "real", "codex")
    assert _outside_resolved(link, ws)
    spelled = os.path.join(str(link), program.name)
    with _metadata_walk(descriptors):
        assert which("codex", _path(link), outside=ws) is None
        assert which("codex", _path(link), outside=ws, fence_program=True) is None
        assert which("codex", _path(link, real.parent), outside=ws, fence_program=True) == str(real)
        assert only_skipped("codex", _path(link), outside=ws) == [
            Hit(path=spelled, entry=str(link), reason="inside_fence")]
        assert only_skipped("codex", _path(link), outside=ws, fence_program=True) == [
            Hit(path=spelled, entry=str(link), reason="inside_fence")]


@pytest.mark.skipif(os.name == "nt", reason="POSIX parent traversal follows directory symlinks")
@pytest.mark.parametrize("descriptors", [True, False], ids=["descriptors", "metadata"])
def test_parent_traversal_spelling_that_enters_the_fence_is_skipped(tmp_path, descriptors):
    from conftest import symlink_or_skip
    ws = tmp_path / "ws"
    _program(ws / "host-bin", "codex")
    outside = tmp_path / "host-bin"
    real = _program(outside, "codex")
    first = tmp_path / "outside" / "deep"
    first.mkdir(parents=True)
    alias = ws / "pivot"
    symlink_or_skip(first, alias, target_is_directory=True)
    entry = str(alias) + os.sep + ".." + os.sep + ".." + os.sep + "host-bin"
    assert _outside_resolved(entry, ws)
    with _metadata_walk(descriptors):
        assert which("codex", _path(entry), outside=ws) is None
        assert which("codex", _path(entry, real.parent), outside=ws) == str(real)
        assert only_skipped("codex", _path(entry), outside=ws) == [
            Hit(path=os.path.join(entry, real.name), entry=entry, reason="inside_fence")]


@pytest.mark.parametrize("descriptors", [True, False], ids=["descriptors", "metadata"])
def test_outside_directory_and_program_symlinks_stay_eligible(tmp_path, descriptors):
    from conftest import symlink_or_skip
    ws = tmp_path / "ws"
    ws.mkdir()
    program = _program(tmp_path / "toolchain", "codex")
    linkdir = tmp_path / "linkbin"
    symlink_or_skip(program.parent, linkdir, target_is_directory=True)
    bindir = tmp_path / "bin"
    bindir.mkdir()
    alias = bindir / ("codex" + EXE)
    symlink_or_skip(program, alias)
    with _metadata_walk(descriptors):
        assert which("codex", _path(linkdir), outside=ws, fence_program=True) == str(linkdir / program.name)
        assert which("codex", _path(bindir), outside=ws, fence_program=True) == str(alias)


def test_a_symlink_cycle_is_skipped_without_searching_it(tmp_path):
    from conftest import symlink_or_skip
    ws = tmp_path / "ws"
    ws.mkdir()
    left = tmp_path / "left"
    left.mkdir()
    right = tmp_path / "right"
    symlink_or_skip(right, left / "cycle", target_is_directory=True)
    symlink_or_skip(left / "cycle", right, target_is_directory=True)
    real = _program(tmp_path / "bin", "codex")
    assert which("codex", _path(right, real.parent), outside=ws) == str(real)
    assert which("codex", _path(right), outside=ws) is None


def test_an_over_budget_entry_is_skipped_before_resolution(tmp_path):
    from types import SimpleNamespace
    from aegis_core import pathlookup
    ws = tmp_path / "ws"
    ws.mkdir()
    real = _program(tmp_path / "bin", "codex")
    huge = os.sep + os.sep.join(["component"] * 513)
    original = pathlookup.os

    def realpath(path):
        text = os.fspath(path)
        if text == huge or text.count(os.sep) > 500:
            raise AssertionError("over-budget entry reached resolution")
        return os.path.realpath(path)

    pathlookup.os = SimpleNamespace(**{**vars(os), "path": SimpleNamespace(
        **{**vars(os.path), "realpath": realpath})})
    try:
        assert which("codex", _path(huge, real.parent), outside=ws) == str(real)
    finally:
        pathlookup.os = original


@pytest.mark.parametrize("case", ["type", "os", "value", "runtime"])
def test_git_fence_propagates_a_caller_fspath_exception(case):
    from aegis_core import pathlookup
    failures = {"type": TypeError, "os": OSError, "value": ValueError, "runtime": RuntimeError}

    class MalformedPath(os.PathLike):
        def __fspath__(self):
            raise failures[case]("private-path-protocol-diagnostic")

    with pytest.raises(failures[case], match="^private-path-protocol-diagnostic$"):
        pathlookup.git_fence(MalformedPath())


@pytest.mark.parametrize("cwd", [123, 12.5], ids=["int", "float"])
def test_git_fence_refuses_an_unsupported_cwd_type(cwd):
    from aegis_core import pathlookup
    assert pathlookup.git_fence(cwd) == os.path.normcase(os.path.abspath(os.sep))


def test_git_fence_refuses_a_non_string_fspath_result(tmp_path):
    from aegis_core import pathlookup

    class MalformedPath(os.PathLike):
        def __fspath__(self):
            return 42

    class BytesPath(os.PathLike):
        def __fspath__(self):
            return os.fsencode(str(tmp_path))

    assert pathlookup.git_fence(MalformedPath()) == os.path.normcase(os.path.abspath(os.sep))
    assert pathlookup.git_fence(BytesPath()) == pathlookup.git_fence(str(tmp_path))


def test_ordinary_refusal_canonicalizes_redacts_then_truncates_its_fence():
    from types import SimpleNamespace
    from aegis_core import gitsafe, pathlookup
    secret = "ghp_" + "A" * 40
    root = os.sep + "root-" + secret + "\n" + os.sep + "tail-" + "x" * 400
    original, probe = pathlookup.os, pathlookup.descriptor_fence_supported
    fake_path = SimpleNamespace(**{**vars(os.path), "realpath": lambda path: os.fspath(path),
        "islink": lambda path: False, "isfile": lambda path: False, "lexists": lambda path: False})
    pathlookup.os = SimpleNamespace(**{**vars(os), "path": fake_path,
        "environ": {"PATH": ""}, "getcwd": lambda: root})
    pathlookup.descriptor_fence_supported = lambda: False
    gitsafe._reset_for_tests()
    try:
        with pytest.raises(gitsafe.GitError) as caught:
            gitsafe.git_executable()
        message = str(caught.value)
        assert caught.value.code == "ERR_AEGIS"
        assert secret not in message and "\n" not in message
        shown = message.split("enclosing checkout ", 1)[1]
        assert shown == os.path.normcase(os.path.abspath(os.sep))
        view = pathlookup._RootCache(pathlookup.GitCache(), root)
        redacted = str(view.error(gitsafe.GitError)("git is not installed or not on PATH"))
        assert secret not in redacted and "\n" not in redacted and "[REDACTED" in redacted
        assert len(redacted.split("enclosing checkout ", 1)[1]) <= 256
    finally:
        pathlookup.os = original
        pathlookup.descriptor_fence_supported = probe
        gitsafe._reset_for_tests()


@pytest.mark.usefixtures("clean_checkout_ancestors")
def test_a_cwd_alias_into_an_unmarked_subdirectory_keeps_the_outer_workspace(tmp_path):
    """A symlink into an unmarked subdirectory cannot shrink the physical checkout."""
    from conftest import symlink_or_skip
    from aegis_core import pathlookup
    workspace = tmp_path / "workspace"
    (workspace / "sub").mkdir(parents=True)
    (workspace / ".git").mkdir()
    owner = tmp_path / "owner"
    owner.mkdir()
    jump = owner / "jump"
    symlink_or_skip(workspace / "sub", jump, target_is_directory=True)
    expected = os.path.normcase(os.path.realpath(workspace))
    assert os.path.normcase(pathlookup.git_fence(jump, descriptors=False)) == expected
    if pathlookup.descriptor_fence_supported():
        assert os.path.normcase(pathlookup.git_fence(jump)) == expected


def _nested_alias(tmp_path, form):
    """/a/one -> /a/two -> /b, workspace /b/ws, shadow program at /a/ws/bin."""
    from conftest import symlink_or_skip
    base = tmp_path / "nest"
    a, b = base / "a", base / "b"
    (b / "ws").mkdir(parents=True)
    a.mkdir()
    if form == "absolute":
        symlink_or_skip(a / "two", a / "one", target_is_directory=True)
    else:
        symlink_or_skip("two", a / "one", target_is_directory=True)
    symlink_or_skip(b, a / "two", target_is_directory=True)
    shadow = _program(a / "ws" / "bin", "codex")
    _program(b / "ws" / "bin", "codex")
    return a, b, shadow


@pytest.mark.parametrize("form", ["absolute", "relative"])
@pytest.mark.parametrize("descriptors", [False, True], ids=["metadata", "descriptors"])
def test_nested_symlinks_keep_the_walked_physical_location(tmp_path, form, descriptors):
    from aegis_core import pathlookup
    if descriptors and not pathlookup.descriptor_fence_supported():
        pytest.skip("descriptor walk is unavailable")
    a, b, shadow = _nested_alias(tmp_path, form)
    real = _program(tmp_path / "host", "codex")
    entry = a / "one" / "ws" / "bin"
    fence = b / "ws"
    with _metadata_walk(descriptors):
        assert which("codex", _path(entry), outside=fence, fence_program=True) is None
        assert which("codex", _path(entry, real.parent), outside=fence, fence_program=True) == str(real)
        assert str(shadow) != str(real)


@pytest.mark.usefixtures("clean_checkout_ancestors")
def test_a_cached_nested_symlink_path_is_dropped_and_an_outside_path_hits(tmp_path):
    from aegis_core import pathlookup
    a, b, shadow = _nested_alias(tmp_path, "absolute")
    real = _program(tmp_path / "host", "codex")
    cache = pathlookup.GitCache()
    view = cache.for_cwd(b / "ws")
    view[("git",)] = str(a / "one" / "ws" / "bin" / shadow.name)
    assert view.get(("git",)) is None
    view[("git",)] = str(real)
    assert view.get(("git",)) == str(real)


def test_an_injected_junction_into_the_fence_is_skipped(tmp_path):
    """Platforms without junctions still observe a mount-point reparse into the fence."""
    ws = tmp_path / "ws"
    host = tmp_path / "host"
    alias = host / "alias"
    planted = _program(alias, "codex")
    real = _program(tmp_path / "real", "codex")

    def observer(text):
        if os.path.normcase(text) == os.path.normcase(str(alias)):
            return ("link", str(ws / "bin"))
        return None

    with _observe_reparse(observer):
        assert which("codex", _path(alias), outside=ws, descriptors=False) is None
        assert which("codex", _path(alias, real.parent), outside=ws, descriptors=False) == str(real)
    assert planted.is_file()


def test_an_unsupported_reparse_point_is_refused(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    alias = tmp_path / "host" / "alias"
    _program(alias, "codex")
    real = _program(tmp_path / "real", "codex")

    def observer(text):
        if os.path.normcase(text) == os.path.normcase(str(alias)):
            return ("unsupported", None)
        return None

    with _observe_reparse(observer):
        assert which("codex", _path(alias), outside=ws, descriptors=False) is None
        assert which("codex", _path(alias, real.parent), outside=ws, descriptors=False) == str(real)


@pytest.mark.skipif(os.name != "nt", reason="directory junctions are a Windows reparse form")
def test_a_windows_junction_into_the_fence_is_skipped(tmp_path):
    import subprocess
    ws = tmp_path / "ws"
    _program(ws / "bin", "codex")
    link = tmp_path / "host" / "alias"
    link.parent.mkdir()
    subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(ws / "bin")], check=True, capture_output=True)
    real = _program(tmp_path / "real", "codex")
    assert which("codex", _path(link), outside=ws, descriptors=False) is None
    assert which("codex", _path(link, real.parent), outside=ws, descriptors=False) == str(real)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX fifo")
def test_a_fifo_path_entry_does_not_block_resolution(tmp_path):
    import signal
    from aegis_core import pathlookup
    ws = tmp_path / "ws"
    ws.mkdir()
    fifo = tmp_path / "fifo-entry"
    os.mkfifo(fifo)
    real = _program(tmp_path / "bin", "codex")
    assert pathlookup._provenance_inside(str(fifo), str(ws), descriptors=False) is True

    def lookup(descriptors):
        return which("codex", _path(fifo, real.parent), outside=ws, descriptors=descriptors)

    def bounded(descriptors):
        if hasattr(signal, "setitimer"):
            signal.signal(signal.SIGALRM, lambda *_args: (_ for _ in ()).throw(TimeoutError("fifo lookup blocked")))
            signal.setitimer(signal.ITIMER_REAL, 2)
        try:
            return lookup(descriptors)
        finally:
            if hasattr(signal, "setitimer"):
                signal.setitimer(signal.ITIMER_REAL, 0)

    assert bounded(False) == str(real)
    if pathlookup.descriptor_fence_supported():
        assert bounded(None) == str(real)


@pytest.mark.usefixtures("clean_checkout_ancestors")
def test_a_cache_miss_clears_only_the_current_fence(tmp_path):
    from aegis_core import pathlookup
    left_root = tmp_path / "left"
    right_root = tmp_path / "right"
    (left_root / ".git").mkdir(parents=True)
    (right_root / ".git").mkdir(parents=True)
    real = _program(tmp_path / "host", "codex")
    cache = pathlookup.GitCache()
    left, right = cache.for_cwd(left_root), cache.for_cwd(right_root)
    assert left.fence != right.fence
    left[("git",)] = str(real)
    right[("git",)] = str(real)
    left.clear()
    assert ("git",) not in [key[1] for key in cache if isinstance(key, tuple) and key[0] == left.fence]
    assert right.get(("git",)) == str(real)


def _symlink_chain(root, hops: int):
    """``hops`` directory links, the last of which names a real directory."""
    from conftest import symlink_or_skip
    final = root / "final"
    final.mkdir(parents=True)
    current = final
    entry = final
    for index in range(hops):
        entry = root / f"hop{index}"
        symlink_or_skip(current, entry, target_is_directory=True)
        current = entry
    return entry


def test_link_hops_stop_at_the_cap_for_the_whole_walk(tmp_path):
    """One counter covers every link the walk follows, including ones after a nested target."""
    from aegis_core import pathlookup
    ws = tmp_path / "ws"
    ws.mkdir()
    short = _symlink_chain(tmp_path / "short", 5)
    planted = _program(tmp_path / "short" / "final", "codex")
    real = _program(tmp_path / "host", "codex")
    allowed = _symlink_chain(tmp_path / "allowed", 40)
    refused = _symlink_chain(tmp_path / "refused", 41)
    assert pathlookup._provenance_inside(str(allowed), str(ws), descriptors=False) is False
    assert pathlookup._provenance_inside(str(refused), str(ws), descriptors=False) is True
    assert which("codex", _path(short, real.parent), outside=ws, descriptors=False) == str(short / planted.name)
    if pathlookup.descriptor_fence_supported():
        assert pathlookup._provenance_inside(str(allowed), str(ws)) is False
        assert pathlookup._provenance_inside(str(refused), str(ws)) is True


def test_a_windows_rooted_path_uses_the_current_drive():
    """``\\ws\\bin`` is on the cwd drive. Lexical collapse must not hide a visit to the fence."""
    import ntpath
    import stat as statmod
    from types import SimpleNamespace
    from aegis_core import pathlookup, primitives
    fence = r"C:\ws"
    original, primitive_os, original_sys = pathlookup.os, primitives.os, pathlookup.sys
    def rooted_isabs(path):
        # Python 3.13 ntpath.isabs('\\\\ws\\\\bin') is false. Model that here so 3.12 cannot hide it.
        text = os.fspath(path)
        if text[:1] in "\\/" and text[1:2] not in "\\/":
            return False
        return ntpath.isabs(text)

    paths = SimpleNamespace(**{**vars(ntpath), "realpath": lambda path: path, "isabs": rooted_isabs,
        "islink": lambda path: False, "isfile": lambda path: True, "lexists": lambda path: False})

    def lstat(path, *args, **kwargs):
        return SimpleNamespace(st_mode=statmod.S_IFDIR, st_file_attributes=0, st_reparse_tag=0)

    modeled = SimpleNamespace(**{**vars(original), "name": "nt", "sep": "\\", "altsep": "/",
        "pathsep": ";", "path": paths, "getcwd": lambda: r"C:\host", "lstat": lstat,
        "access": lambda *args, **kwargs: True, "listdir": lambda directory: ["git.exe"],
        "environ": {"PATHEXT": ".EXE"}})
    pathlookup.os = primitives.os = modeled
    pathlookup.sys = SimpleNamespace(**{**vars(original_sys), "platform": "win32"})
    try:
        assert pathlookup._provenance_inside(r"\ws\bin", fence, descriptors=False) is True
        assert pathlookup._provenance_inside(r"\outside\..\ws\..\outside\bin", fence, descriptors=False) is True
        assert pathlookup._provenance_inside(r"\host\..\other\bin", fence, descriptors=False) is False
        assert pathlookup.which("git.exe", path=r"\ws\bin", outside=fence, fence_program=True, descriptors=False) is None
        assert pathlookup.which("git.exe", path=r"\host\bin", outside=fence, fence_program=True, descriptors=False) == ntpath.join(r"\host\bin", "git.exe")
        skipped = pathlookup.only_skipped("git.exe", path=r"\ws\bin", outside=fence, fence_program=True)
        assert skipped and skipped[0].reason == pathlookup.INSIDE_FENCE
        modeled.getcwd = lambda: r"D:\host"
        assert pathlookup._provenance_inside(r"\ws\bin", fence, descriptors=False) is False
    finally:
        pathlookup.os, primitives.os = original, primitive_os
        pathlookup.sys = original_sys


@pytest.mark.skipif(os.name == "nt", reason="POSIX execute-only mode")
def test_an_execute_only_outside_program_stays_selectable(tmp_path):
    """A leaf the caller can run but not read is outside. Opening it for the type check must not refuse it."""
    from aegis_core import pathlookup
    if not pathlookup.descriptor_fence_supported():
        pytest.skip("descriptor walk is unavailable")
    ws = tmp_path / "ws"
    ws.mkdir()
    locked = _program(tmp_path / "locked", "codex")
    os.chmod(locked, 0o111)
    real = _program(tmp_path / "host", "codex")
    assert which("codex", _path(locked.parent, real.parent), outside=ws, fence_program=True) == str(locked)
    assert only_skipped("codex", _path(locked.parent), outside=ws, fence_program=True) == []


def test_nested_link_targets_share_one_hop_counter(tmp_path):
    """A target that links, continues, and links again spends the hops already used.

    Six stages of ``../d{n}/s/../../d{n}/s`` follow 63 links. A counter that resets
    when a nested target returns would accept them. The cap is 40.
    """
    from conftest import symlink_or_skip
    from aegis_core import pathlookup
    root = tmp_path / "shape"
    fence = root / "fence"
    fence.mkdir(parents=True)
    stages = 6
    for index in range(stages + 1):
        (root / f"d{index}").mkdir()
    (root / f"d{stages}" / "s").mkdir()
    for index in range(stages):
        symlink_or_skip(f"../d{index + 1}/s/../../d{index + 1}/s", root / f"d{index}" / "s", target_is_directory=True)
    entry = root / "d0" / "s"
    _program(root / f"d{stages}" / "s", "codex")
    real = _program(tmp_path / "host", "codex")
    assert pathlookup._provenance_inside(str(entry), str(fence), descriptors=False) is True
    assert which("codex", _path(entry, real.parent), outside=fence, descriptors=False) == str(real)
    if pathlookup.descriptor_fence_supported():
        assert pathlookup._provenance_inside(str(entry), str(fence)) is True


def _volume() -> str:
    return os.path.normcase(os.path.abspath(os.sep))


def _marker(path):
    (path / ".git").mkdir(parents=True, exist_ok=True)
    return path


def _both_modes(cwd):
    """Metadata and, when the host can, descriptor discovery of one cwd."""
    from aegis_core import pathlookup
    found = [pathlookup.git_fence(cwd, descriptors=False)]
    if pathlookup.descriptor_fence_supported():
        found.append(pathlookup.git_fence(cwd))
    return found


@pytest.fixture
def clean_checkout_ancestors(tmp_path):
    """Model a clean host around synthetic checkouts; keep every fixture marker."""
    from types import SimpleNamespace
    from aegis_core import pathlookup
    original = pathlookup.os
    base = os.path.normcase(os.path.realpath(tmp_path))

    def inside(path):
        key = os.path.normcase(os.path.realpath(path))
        return key == base or key.startswith(base + os.sep)

    def lexists(path):
        if os.path.basename(path) == ".git" and not inside(os.path.dirname(path)):
            return False
        return os.path.lexists(path)

    def stat(path, *args, **kwargs):
        parent = kwargs.get("dir_fd")
        if path == ".git" and parent is not None:
            if not inside(pathlookup._fd_location(parent)):
                raise FileNotFoundError(2, "marker outside fixture model")
        elif os.path.basename(path) == ".git" and not inside(os.path.dirname(path)):
            raise FileNotFoundError(2, "marker outside fixture model")
        return os.stat(path, *args, **kwargs)

    pathlookup.os = SimpleNamespace(**{**vars(original), "stat": stat,
        "path": SimpleNamespace(**{**vars(original.path), "lexists": lexists})})
    try:
        yield
    finally:
        pathlookup.os = original


@pytest.mark.usefixtures("clean_checkout_ancestors")
def test_raw_cwd_dotdot_keeps_the_checkout_abspath_would_skip(tmp_path):
    """``/owner/jump/../sub`` must see the checkout ``jump`` enters, not the collapsed spelling."""
    from conftest import symlink_or_skip
    from aegis_core import pathlookup
    owner = tmp_path / "owner"
    owner.mkdir()
    ws = _marker(tmp_path / "ws")
    (ws / "deep").mkdir()
    (ws / "sub").mkdir()
    jump = owner / "jump"
    symlink_or_skip(ws / "deep", jump, target_is_directory=True)
    cwd = str(jump) + os.sep + ".." + os.sep + "sub"
    expected = os.path.normcase(os.path.realpath(ws))
    assert _both_modes(cwd) == ([expected, expected] if pathlookup.descriptor_fence_supported() else [expected])
    planted = _program(ws / "bin", "git")
    real = _program(tmp_path / "host", "git")
    fence = pathlookup.git_fence(cwd, descriptors=False)
    assert which("git", _path(ws / "bin"), outside=fence, descriptors=False) is None
    assert which("git", _path(ws / "bin", real.parent), outside=fence, descriptors=False) == str(real)
    assert planted.is_file()


@pytest.mark.usefixtures("clean_checkout_ancestors")
def test_disjoint_checkouts_fence_the_whole_volume(tmp_path):
    from conftest import symlink_or_skip
    from aegis_core import pathlookup
    ws = _marker(tmp_path / "ws")
    other = _marker(tmp_path / "other")
    jump = ws / "jump"
    symlink_or_skip(other, jump, target_is_directory=True)
    assert _both_modes(jump) == [_volume()] * (2 if pathlookup.descriptor_fence_supported() else 1)
    planted = _program(ws / "bin", "git")
    fence = pathlookup.git_fence(jump, descriptors=False)
    assert which("git", _path(planted.parent), outside=fence, descriptors=False) is None


@pytest.mark.usefixtures("clean_checkout_ancestors")
def test_a_descriptor_alias_keeps_the_workspace_marker(tmp_path):
    """``/alias -> /base`` then ``ws/jump -> /outside`` must not discover ``/outside``."""
    from conftest import symlink_or_skip
    from aegis_core import pathlookup
    base = tmp_path / "base"
    ws = _marker(base / "ws")
    alias = tmp_path / "alias"
    symlink_or_skip(base, alias, target_is_directory=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    jump = ws / "jump"
    symlink_or_skip(outside, jump, target_is_directory=True)
    cwd = alias / "ws" / "jump"
    expected = os.path.normcase(os.path.realpath(ws))
    assert _both_modes(cwd) == [expected] * (2 if pathlookup.descriptor_fence_supported() else 1)
    planted = _program(ws / "bin", "git")
    assert which("git", _path(planted.parent), outside=pathlookup.git_fence(cwd, descriptors=False), descriptors=False) is None


@pytest.mark.usefixtures("clean_checkout_ancestors")
def test_dotdot_through_a_pivot_still_records_the_workspace(tmp_path):
    from conftest import symlink_or_skip
    from aegis_core import pathlookup
    home = tmp_path / "home" / "u"
    ws = _marker(home / "ws")
    man = tmp_path / "usr" / "share" / "man" / "man1"
    man.mkdir(parents=True)
    pivot = ws / "pivot"
    symlink_or_skip(man, pivot, target_is_directory=True)
    (tmp_path / "elsewhere").mkdir()
    cwd = str(pivot) + (os.sep + "..") * 4 + os.sep + "elsewhere"
    expected = os.path.normcase(os.path.realpath(ws))
    assert _both_modes(cwd) == [expected] * (2 if pathlookup.descriptor_fence_supported() else 1)
    planted = _program(ws / "bin", "git")
    assert which("git", _path(planted.parent), outside=pathlookup.git_fence(cwd, descriptors=False), descriptors=False) is None


@pytest.mark.usefixtures("clean_checkout_ancestors")
def test_a_symlinked_prefix_does_not_drop_the_workspace_marker(tmp_path):
    """macOS ``/var -> private/var`` plus ``ws/jump -> /usr`` stays on the workspace."""
    from conftest import symlink_or_skip
    from aegis_core import pathlookup
    private = tmp_path / "private" / "var"
    ws = _marker(private / "ws")
    var = tmp_path / "var"
    symlink_or_skip("private/var", var, target_is_directory=True)
    usr = tmp_path / "usr"
    usr.mkdir()
    jump = private / "ws" / "jump"
    symlink_or_skip(usr, jump, target_is_directory=True)
    cwd = var / "ws" / "jump"
    expected = os.path.normcase(os.path.realpath(ws))
    assert _both_modes(cwd) == [expected] * (2 if pathlookup.descriptor_fence_supported() else 1)


@pytest.mark.usefixtures("clean_checkout_ancestors")
def test_a_link_remainder_past_the_component_cap_fences_the_volume(tmp_path):
    """Splicing a link while keeping the previous remainder past 512 components refuses."""
    from conftest import symlink_or_skip
    from aegis_core import pathlookup
    ws = _marker(tmp_path / "workspace")
    sub = ws / "sub"
    sub.mkdir()
    owner = tmp_path / "owner"
    owner.mkdir()
    jump = owner / "jump"
    symlink_or_skip(sub, jump, target_is_directory=True)
    rest = (os.sep + ".." + os.sep + "sub") * 150
    symlink_or_skip("." + rest, sub / "l2", target_is_directory=True)
    symlink_or_skip("l2" + rest, sub / "l1", target_is_directory=True)
    cwd = jump / "l1"
    assert _both_modes(cwd) == [_volume()] * (2 if pathlookup.descriptor_fence_supported() else 1)
    planted = _program(ws / "bin", "git")
    fence = pathlookup.git_fence(str(cwd), descriptors=False)
    assert fence == _volume()
    assert which("git", _path(planted.parent), outside=fence, descriptors=False) is None


@pytest.mark.usefixtures("clean_checkout_ancestors")
def test_an_escape_after_a_marked_ancestor_keeps_that_checkout(tmp_path):
    """``jump -> workspace/sub`` then ``escape -> outside`` stays on the ancestor checkout."""
    from conftest import symlink_or_skip
    from aegis_core import pathlookup
    ws = _marker(tmp_path / "workspace")
    sub = ws / "sub"
    sub.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    symlink_or_skip(outside, sub / "escape", target_is_directory=True)
    owner = tmp_path / "owner"
    owner.mkdir()
    jump = owner / "jump"
    symlink_or_skip(sub, jump, target_is_directory=True)
    cwd = jump / "escape"
    expected = os.path.normcase(os.path.realpath(ws))
    assert _both_modes(cwd) == [expected] * (2 if pathlookup.descriptor_fence_supported() else 1)
    _marker(sub)
    assert _both_modes(cwd) == [expected] * (2 if pathlookup.descriptor_fence_supported() else 1)
    planted = _program(ws / "bin", "git")
    assert which("git", _path(planted.parent), outside=pathlookup.git_fence(str(cwd), descriptors=False), descriptors=False) is None


@pytest.mark.usefixtures("clean_checkout_ancestors")
def test_an_unproven_cwd_link_fences_the_volume(tmp_path):
    from conftest import symlink_or_skip
    from aegis_core import pathlookup
    ws = _marker(tmp_path / "ws")
    (ws / "sub").mkdir()
    (ws / "deep").mkdir()
    owner = tmp_path / "owner"
    owner.mkdir()
    chain = tmp_path / "hops"
    chain.mkdir()
    current = ws / "sub"
    for index in range(41):
        link = chain / f"hop{index}"
        symlink_or_skip(current, link, target_is_directory=True)
        current = link
    hops = current
    dotted = owner / "jump"
    target = str(ws) + (os.sep + ".") * 600 + os.sep + "deep"
    symlink_or_skip(target, dotted, target_is_directory=True)
    assert _both_modes(hops) == [_volume()] * (2 if pathlookup.descriptor_fence_supported() else 1)
    assert _both_modes(dotted) == [_volume()] * (2 if pathlookup.descriptor_fence_supported() else 1)
    planted = _program(ws / "bin", "git")
    fence = pathlookup.git_fence(dotted, descriptors=False)
    assert fence == _volume()
    assert which("git", _path(planted.parent), outside=fence, descriptors=False) is None


@pytest.mark.usefixtures("clean_checkout_ancestors")
def test_an_unsupported_cwd_reparse_fences_the_volume(tmp_path):
    from aegis_core import pathlookup
    alias = tmp_path / "alias"
    alias.mkdir()
    ws = _marker(tmp_path / "ws")
    (ws / "sub").mkdir()

    def observer(text):
        if os.path.normcase(text) == os.path.normcase(str(alias)):
            return ("unsupported", None)
        return None

    with _observe_reparse(observer):
        assert pathlookup.git_fence(alias, descriptors=False) == _volume()
    assert pathlookup.git_fence(ws, descriptors=False) == os.path.normcase(os.path.realpath(ws))


def test_a_walk_cannot_descend_through_a_regular_file(tmp_path):
    from aegis_core import pathlookup
    ws = tmp_path / "ws"
    ws.mkdir()
    outside = tmp_path / "outside"
    regular = outside / "regular"
    regular.parent.mkdir()
    regular.write_bytes(b"not-a-directory")
    _program(outside / "bin", "codex")
    entry = str(regular) + os.sep + ".." + os.sep + "bin"
    assert pathlookup._provenance_inside(entry, str(ws), descriptors=False) is True
    assert which("codex", _path(entry), outside=ws, descriptors=False) is None
    if pathlookup.descriptor_fence_supported():
        assert pathlookup._provenance_inside(entry, str(ws)) is True


def test_a_trailing_separator_does_not_split_one_directory(tmp_path):
    from aegis_core import pathlookup
    ws = tmp_path / "ws"
    (ws / "bin").mkdir(parents=True)
    spelled = str(ws) + os.sep
    assert pathlookup._component_inside(str(ws), spelled) is True
    assert pathlookup._component_inside(spelled, str(ws)) is True
    assert pathlookup._provenance_inside(str(ws / "bin"), spelled, descriptors=False) is True


def test_real_key_none_refuses_a_walk_that_stayed_outside(tmp_path):
    from aegis_core import pathlookup
    ws = tmp_path / "ws"
    ws.mkdir()
    program = _program(tmp_path / "host" / "bin", "codex")
    previous = pathlookup._real_key_observer

    def observer(path):
        return None

    pathlookup._real_key_observer = observer
    try:
        assert pathlookup._provenance_inside(str(program.parent), str(ws), descriptors=False) is True
        assert which("codex", _path(program.parent), outside=ws, descriptors=False) is None
    finally:
        pathlookup._real_key_observer = previous


def test_windows_short_names_trailing_dots_and_rooted_links_stay_closed():
    """8.3 and trailing-dot aliases are real_key; ``..`` collapse is abspath; rooted links use the walked drive."""
    import ntpath
    from types import SimpleNamespace
    from aegis_core import pathlookup, primitives
    fence = r"C:\workspace"
    hostile = r"C:\bin"
    original, primitive_os, original_sys = pathlookup.os, primitives.os, pathlookup.sys
    previous_key, previous_reparse = pathlookup._real_key_observer, pathlookup._reparse_observer

    def lstat(path, *args, **kwargs):
        return SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=0, st_reparse_tag=0)

    paths = SimpleNamespace(**{**vars(ntpath), "realpath": lambda path: os.fspath(path),
        "islink": lambda path: False, "isfile": lambda path: True, "lexists": lambda path: False})
    modeled = SimpleNamespace(**{**vars(original), "name": "nt", "sep": "\\", "altsep": "/",
        "pathsep": ";", "path": paths, "getcwd": lambda: r"C:\host", "lstat": lstat,
        "access": lambda *args, **kwargs: True, "listdir": lambda directory: ["git.exe"],
        "environ": {"PATHEXT": ".EXE"}})

    def observer(path):
        text = ntpath.normcase(os.fspath(path))
        for alias in (r"c:\worksp~1", r"c:\workspace."):
            if text.startswith(alias):
                return ntpath.normcase(ntpath.normpath(r"C:\workspace" + text[len(alias):]))
        return pathlookup._REAL_KEY_FALLBACK

    pathlookup.os = primitives.os = modeled
    pathlookup.sys = SimpleNamespace(**{**vars(original_sys), "platform": "win32"})
    pathlookup._real_key_observer = observer
    try:
        assert pathlookup._provenance_inside(r"C:\workspace.\bin", fence, descriptors=False) is True
        assert pathlookup._provenance_inside(r"C:\WORKSP~1\bin", fence, descriptors=False) is True
        assert pathlookup._provenance_inside(r"C:\WORKSP~1\..\host", fence, descriptors=False) is True
        assert pathlookup.which("git.exe", path=r"C:\WORKSP~1\bin", outside=fence, fence_program=True, descriptors=False) is None
        cache = pathlookup.GitCache()
        view = pathlookup._RootCache(cache, ntpath.normcase(fence))
        view[("git",)] = r"C:\WORKSP~1\bin\git.exe"
        assert view.get(("git",)) is None

        def junction(text):
            if ntpath.normcase(os.fspath(text)) == ntpath.normcase(r"C:\g"):
                return ("link", r"C:\tools\git\sub")
            return None

        pathlookup._reparse_observer = junction
        assert pathlookup._provenance_inside(r"C:\g\..\bin", hostile, descriptors=False) is True

        for drive, other in (("C:", "D:"), ("D:", "C:")):
            link = drive + r"\outside\link"

            def rooted(text):
                return ("link", r"\ws\bin") if ntpath.normcase(os.fspath(text)) == ntpath.normcase(link) else None

            pathlookup._reparse_observer = rooted
            assert pathlookup._provenance_inside(link, other + r"\ws", descriptors=False) is False
            assert pathlookup._provenance_inside(link, drive + r"\ws", descriptors=False) is True
            assert pathlookup.which(
                "git.exe", path=link, outside=drive + r"\ws", fence_program=True, descriptors=False,
            ) is None
            cross = pathlookup._RootCache(pathlookup.GitCache(), ntpath.normcase(drive + r"\ws"))
            cross[("git",)] = link + r"\git.exe"
            assert cross.get(("git",)) is None
        assert pathlookup._relative_parts("C:sub") is None
        assert pathlookup._fence_raw("C:sub") is None
        assert pathlookup._splice_target(r"\ws\bin", [], "D:")[0] == "D:"

        # The execution cwd also follows Win32 normalization. Prove the raw walk
        # first, then inspect the canonical cwd without discarding either checkout.
        pathlookup._reparse_observer = junction
        paths.realpath = lambda path: ntpath.normpath(os.fspath(path))
        paths.isfile = lambda path: path.endswith("git.exe")

        def marker_stat(path, *args, **kwargs):
            if ntpath.normcase(path) == ntpath.normcase(r"C:\bin\.git"):
                return SimpleNamespace(st_mode=stat.S_IFDIR)
            raise FileNotFoundError(2, "no modeled marker")

        modeled.stat = marker_stat
        assert pathlookup.git_fence(r"C:\g\..\bin", descriptors=False) == ntpath.normcase(r"C:\bin")
    finally:
        pathlookup.os, primitives.os = original, primitive_os
        pathlookup.sys = original_sys
        pathlookup._real_key_observer = previous_key
        pathlookup._reparse_observer = previous_reparse


@pytest.mark.usefixtures("clean_checkout_ancestors")
def test_concurrent_partition_misses_do_not_raise(tmp_path):
    """Two clears of one fence must not KeyError, and must leave the other fence."""
    import time
    from threading import Thread
    from aegis_core import pathlookup
    left_root, right_root = _marker(tmp_path / "left"), _marker(tmp_path / "right")
    real = _program(tmp_path / "host", "codex")

    class Slow(pathlookup.GitCache):
        def __iter__(self):
            keys = list(dict.keys(self))
            for key in keys:
                time.sleep(0.002)
                yield key

    cache = Slow()
    left, right = cache.for_cwd(left_root), cache.for_cwd(right_root)
    for index in range(30):
        left[("git", index)] = str(real)
        right[("git", index)] = str(real)
    errors = []

    def hammer(view):
        try:
            view.clear()
        except Exception as exc:
            errors.append(exc)

    workers = [Thread(target=hammer, args=(left,)) for _ in range(2)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(20)
    assert not errors and not any(worker.is_alive() for worker in workers)
    assert right.get(("git", 0)) == str(real)
    cache.clear()
    assert list(cache) == []


def test_descriptor_fence_closes_the_entered_directory_when_marker_recording_fails(tmp_path):
    from aegis_core import pathlookup
    if not pathlookup.descriptor_fence_supported() or not os.path.isdir("/proc/self/fd"):
        pytest.skip("descriptor counting requires procfs")
    ws = _marker(tmp_path / "ws")
    original = pathlookup._record_markers

    def record(path, markers):
        if os.path.normcase(path) == os.path.normcase(str(ws)):
            raise OSError(13, "marker inspection failed")
        return original(path, markers)

    before = len(os.listdir("/proc/self/fd"))
    pathlookup._record_markers = record
    try:
        assert pathlookup.git_fence(ws) == _volume()
    finally:
        pathlookup._record_markers = original
    assert len(os.listdir("/proc/self/fd")) == before
    assert pathlookup.git_fence(ws) == _outer_marker_fence(ws)


def test_cwd_byte_budget_is_checked_before_decoding():
    from types import SimpleNamespace
    from aegis_core import pathlookup
    original = pathlookup.os
    large = b"x" * 16385

    def decode(value):
        assert value is not large, "oversized cwd reached decoding"
        return os.fsdecode(value)

    pathlookup.os = SimpleNamespace(**{**vars(original), "fsdecode": decode})
    try:
        assert pathlookup.git_fence(large) == _volume()
    finally:
        pathlookup.os = original


def test_link_byte_budget_is_checked_before_decoding(tmp_path):
    from types import SimpleNamespace
    from aegis_core import pathlookup
    original, previous = pathlookup.os, pathlookup._reparse_observer
    large = b"x" * 16385
    ws = tmp_path / "ws"
    ws.mkdir()
    alias = tmp_path / "alias"
    alias.mkdir()
    real = _program(tmp_path / "host", "codex")

    def decode(value):
        assert value is not large, "oversized link reached decoding"
        return os.fsdecode(value)

    def observer(path):
        return ("link", large) if path == str(alias) else None

    pathlookup.os = SimpleNamespace(**{**vars(original), "fsdecode": decode})
    pathlookup._reparse_observer = observer
    try:
        assert which("codex", _path(alias, real.parent), outside=ws, descriptors=False) == str(real)
    finally:
        pathlookup.os, pathlookup._reparse_observer = original, previous


def test_cache_iteration_survives_another_partition_write(tmp_path, clean_checkout_ancestors):
    from threading import Thread
    from aegis_core import pathlookup
    left_root, right_root = _marker(tmp_path / "left"), _marker(tmp_path / "right")
    cache = pathlookup.GitCache()
    left, right = cache.for_cwd(left_root), cache.for_cwd(right_root)
    left[("git",)] = "left"
    right[("git",)] = "right"
    initial = set(cache)
    reader = iter(cache)
    first = next(reader)
    worker = Thread(target=lambda: right.__setitem__(("new",), "new"))
    worker.start()
    worker.join(5)
    assert not worker.is_alive()
    assert {first, *reader} == initial


@pytest.mark.parametrize("descriptors", [False, True], ids=["metadata", "descriptors"])
def test_unreadable_marker_metadata_closes_discovery(tmp_path, clean_checkout_ancestors, descriptors):
    from types import SimpleNamespace
    from aegis_core import pathlookup
    if descriptors and not pathlookup.descriptor_fence_supported():
        pytest.skip("no descriptor discovery")
    ws = _marker(tmp_path / "ws")
    original = pathlookup.os

    def stat(path, *args, **kwargs):
        parent = kwargs.get("dir_fd")
        marker = os.path.join(pathlookup._fd_location(parent), path) if parent is not None else os.fspath(path)
        if os.path.normcase(marker) == os.path.normcase(str(ws / ".git")):
            raise PermissionError(13, "marker is unreadable")
        return original.stat(path, *args, **kwargs)

    pathlookup.os = SimpleNamespace(**{**vars(original), "stat": stat})
    try:
        assert pathlookup.git_fence(ws, descriptors=descriptors) == _volume()
    finally:
        pathlookup.os = original
    assert pathlookup.git_fence(ws, descriptors=False) == os.path.normcase(str(ws))


def test_an_unproven_cross_drive_cwd_refuses_programs_on_every_drive():
    import ntpath
    from types import SimpleNamespace
    from aegis_core import pathlookup, primitives
    original, primitive_os, original_sys = pathlookup.os, primitives.os, pathlookup.sys
    previous = pathlookup._reparse_observer
    paths = SimpleNamespace(**{**vars(ntpath), "realpath": lambda path: os.fspath(path),
        "islink": lambda path: False, "isfile": lambda path: True})

    def lstat(path, *args, **kwargs):
        return SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=0, st_reparse_tag=0)

    def marker_stat(path, *args, **kwargs):
        if ntpath.normcase(path) == ntpath.normcase(r"D:\ws\.git"):
            return SimpleNamespace(st_mode=stat.S_IFDIR)
        raise FileNotFoundError(2, "no modeled marker")

    def observer(path):
        text = ntpath.normcase(path)
        if text == ntpath.normcase(r"C:\owner\jump"):
            return ("link", r"D:\ws\sub")
        if text == ntpath.normcase(r"D:\ws\sub\blocked"):
            return ("unsupported", None)
        return None

    modeled = SimpleNamespace(**{**vars(original), "name": "nt", "sep": "\\", "altsep": "/",
        "pathsep": ";", "path": paths, "getcwd": lambda: r"C:\owner", "lstat": lstat,
        "stat": marker_stat, "access": lambda *args: True, "listdir": lambda path: ["git.exe"],
        "environ": {"PATHEXT": ".EXE"}})
    pathlookup.os = primitives.os = modeled
    pathlookup.sys = SimpleNamespace(**{**vars(original_sys), "platform": "win32"})
    pathlookup._reparse_observer = observer
    try:
        fence = pathlookup.git_fence(r"C:\owner\jump\blocked", descriptors=False)
        assert fence == ntpath.normcase("C:\\")
        assert pathlookup.which("git.exe", path=r"D:\ws\bin", outside=fence, descriptors=False) is None
        assert pathlookup.only_skipped("git.exe", path=r"D:\ws\bin", outside=fence)[0].reason == "inside_fence"
        # An explicitly proven volume fence still permits owner programs on another drive.
        assert pathlookup.which("git.exe", path=r"D:\host", outside="C:\\", descriptors=False) is not None
    finally:
        pathlookup.os, primitives.os = original, primitive_os
        pathlookup.sys = original_sys
        pathlookup._reparse_observer = previous


@pytest.fixture
def checkout_process():
    """Own and restore this test's cwd, PATH and ordinary executable cache."""
    from aegis_core import gitsafe, pathlookup
    cwd, search, previous = os.getcwd(), os.environ.get("PATH"), gitsafe._GIT_FOUND
    cache = pathlookup.GitCache()
    gitsafe._GIT_FOUND = cache
    try:
        yield cache
    finally:
        os.chdir(cwd)
        gitsafe._GIT_FOUND = previous
        if search is None:
            os.environ.pop("PATH", None)
        else:
            os.environ["PATH"] = search


@pytest.mark.skipif(os.name != "posix", reason="backslash is a POSIX filename character")
@pytest.mark.parametrize("name", ["repo\\", "repo\\inner"], ids=["trailing", "interior"])
@pytest.mark.parametrize("relative", [".", "sub/.."], ids=["dot", "parent"])
@pytest.mark.parametrize("descriptors", [False, True], ids=["metadata", "descriptors"])
def test_relative_cwd_keeps_literal_backslashes(tmp_path, checkout_process, clean_checkout_ancestors,
                                               name, relative, descriptors):
    from aegis_core import pathlookup
    if descriptors and not pathlookup.descriptor_fence_supported():
        pytest.skip("descriptor-relative discovery is unavailable")
    ws = _marker(tmp_path / name)
    sibling = _marker(tmp_path / name.replace("\\", ""))
    (ws / "sub").mkdir()
    (sibling / "sub").mkdir()
    os.chdir(ws)
    expected = os.path.normcase(str(ws))
    assert pathlookup.git_fence(relative, descriptors=descriptors) == expected
    assert pathlookup.git_fence(sibling, descriptors=descriptors) == str(sibling)


@pytest.mark.skipif(os.name != "posix", reason="backslash is a POSIX filename character")
@pytest.mark.parametrize("name", ["repo\\", "repo\\inner"], ids=["trailing", "interior"])
@pytest.mark.parametrize("relative", [".", "sub/.."], ids=["dot", "parent"])
def test_ordinary_relative_cwd_backslashes_keep_execution_and_cache_separate(
        tmp_path, checkout_process, clean_checkout_ancestors, name, relative):
    from concurrent.futures import ThreadPoolExecutor
    from aegis_core import gitsafe, pathlookup
    ws = _marker(tmp_path / name)
    sibling = _marker(tmp_path / name.replace("\\", ""))
    (ws / "sub").mkdir()
    (sibling / "sub").mkdir()
    planted = _program(ws / "bin", "git", b"#!/bin/sh\nprintf 'workspace-program\\n'\n")
    host = _program(tmp_path / "host", "git", b"#!/bin/sh\nprintf 'host-program\\n'\n")
    cache = checkout_process
    os.chdir(ws)
    os.environ["PATH"] = _path(planted.parent, host.parent)
    other = str(sibling)
    # Prime the sibling partition with the program that our checkout must refuse.
    assert gitsafe.run(["--version"], other).stdout == b"workspace-program\n"
    assert gitsafe.run(["--version"], relative).stdout == b"host-program\n"
    assert cache.for_cwd(relative).fence == str(ws)
    assert cache.for_cwd(other).fence == str(sibling)
    with ThreadPoolExecutor(max_workers=2) as workers:
        own = workers.submit(gitsafe.run, ["--version"], relative)
        foreign = workers.submit(gitsafe.run, ["--version"], other)
        assert own.result(timeout=10).stdout == b"host-program\n"
        assert foreign.result(timeout=10).stdout == b"workspace-program\n"
    os.environ["PATH"] = str(planted.parent)
    for _attempt in range(2):
        with pytest.raises(gitsafe.GitError, match="^git is not installed or not on PATH") as caught:
            gitsafe.run(["--version"], relative)
        assert caught.value.code == "ERR_AEGIS"
    os.environ["PATH"] = _path(planted.parent, host.parent)
    assert gitsafe.run(["--version"], relative).stdout == b"host-program\n"

@contextlib.contextmanager
def _windows_volume_root_model(volume, root_state):
    """Model canonical drive/UNC aliases without creating host reparse points."""
    import ntpath
    from types import SimpleNamespace
    from aegis_core import pathlookup, primitives
    drive = "X:" if volume == "drive" else r"\\server\share"
    root, state = drive + "\\", [root_state]
    alias = ntpath.normcase(drive)

    def canonical(path):
        assert len(path) <= pathlookup._MAX_FENCE_CHARS
        text = ntpath.normcase(ntpath.normpath(path))
        if text == r"c:\alias" or text.startswith("c:\\alias\\"):
            text = root + text[len(r"c:\alias"):].lstrip("\\")
        if text == r"c:\launch\git.exe":
            text = ntpath.join(root, "git.exe")
        current, rest = ntpath.splitdrive(ntpath.normcase(text))
        if current == alias and state[0] != "literal":
            if state[0] == "unproven" and rest in ("", "\\"):
                return None
            backing = {"inside": r"c:\ws", "outside": r"c:\owner",
                       "through_fence": r"c:\ws\hop", "unproven": r"c:\owner"}[state[0]]
            text = backing + rest
        prefix = r"c:\ws\hop"
        if text == prefix or text.startswith(prefix + "\\"):
            text = r"c:\host\bin" + text[len(prefix):]
        return ntpath.normcase(ntpath.normpath(text))

    def reparse(path):
        text = ntpath.normcase(path)
        if text == r"c:\alias":
            return ("link", root)
        if text == r"c:\launch\git.exe":
            return ("link", ntpath.join(root, "git.exe"))
        if text == r"c:\ws\hop":
            return ("link", r"C:\host\bin")
        return None

    def lstat(path):
        return SimpleNamespace(st_mode=stat.S_IFREG if path.endswith(".exe") else stat.S_IFDIR,
                               st_file_attributes=0, st_reparse_tag=0)

    def marker(path, *args, **kwargs):
        if ntpath.normcase(path) == r"c:\ws\.git":
            return SimpleNamespace(st_mode=stat.S_IFDIR)
        raise FileNotFoundError(2, "no modeled marker")

    paths = SimpleNamespace(**{**vars(ntpath), "realpath": canonical,
        "isfile": lambda path: path.endswith(".exe"), "islink": lambda path: False})
    modeled = SimpleNamespace(**{**vars(os), "name": "nt", "sep": "\\", "altsep": "/",
        "pathsep": ";", "path": paths, "getcwd": lambda: r"C:\owner", "lstat": lstat,
        "stat": marker, "listdir": lambda path: ["git.exe"], "access": lambda *args: True,
        "environ": {"PATHEXT": ".EXE", "PATH": r"C:\host\bin"}})
    original, primitive_os, original_sys = pathlookup.os, primitives.os, pathlookup.sys
    previous_key, previous_reparse = pathlookup._real_key_observer, pathlookup._reparse_observer
    pathlookup.os = primitives.os = modeled
    pathlookup.sys = SimpleNamespace(platform="win32")
    pathlookup._real_key_observer, pathlookup._reparse_observer = canonical, reparse
    try:
        yield root, state
    finally:
        pathlookup.os, primitives.os = original, primitive_os
        pathlookup.sys = original_sys
        pathlookup._real_key_observer, pathlookup._reparse_observer = previous_key, previous_reparse


@pytest.mark.parametrize("case", ["entry", "absolute_target", "program", "cache", "discovery"])
@pytest.mark.parametrize("root_state", ["through_fence", "inside", "outside", "unproven"])
@pytest.mark.parametrize("volume", ["drive", "unc"])
def test_windows_root_aliases_are_checked_before_components(case, root_state, volume, checkout_process):
    import ntpath
    from concurrent.futures import ThreadPoolExecutor
    from aegis_core import gitsafe, pathlookup
    fence, host = r"C:\ws", r"C:\host\bin"
    with _windows_volume_root_model(volume, root_state) as (root, state):
        entry = {"entry": root, "absolute_target": r"C:\alias",
                 "program": r"C:\launch", "cache": root, "discovery": root}[case]
        if case == "discovery":
            closed = pathlookup.git_fence(root, descriptors=False)
            assert closed == ntpath.normcase(root)
            assert pathlookup.which("git.exe", path=host, outside=closed, descriptors=False) is None
            with pytest.raises(gitsafe.GitError, match="^git is not installed or not on PATH") as caught:
                gitsafe.git_executable(cwd=root)
            assert caught.value.code == "ERR_AEGIS"
            state[0] = "literal"
            assert gitsafe.git_executable(cwd=root) == ntpath.join(host, "git.exe")
        elif case == "cache":
            view = pathlookup.GitCache().for_cwd(fence)
            program = ntpath.join(entry, "git.exe")
            view["git"], view["host"] = program, ntpath.join(host, "git.exe")
            with ThreadPoolExecutor(max_workers=2) as workers:
                bad = workers.submit(view.get, "git")
                good = workers.submit(view.get, "host")
                assert bad.result(timeout=10) is None
                assert good.result(timeout=10) == ntpath.join(host, "git.exe")
            state[0] = "literal"
            assert view.get("git") == program
        else:
            for _attempt in range(2):
                assert pathlookup.which("git.exe", path=entry, outside=fence,
                                        fence_program=True, descriptors=False) is None
            hits = pathlookup.only_skipped("git.exe", path=entry, outside=fence, fence_program=True)
            assert len(hits) == 1 and hits[0].reason == pathlookup.INSIDE_FENCE
            assert pathlookup.which("git.exe", path=entry + ";" + host, outside=fence,
                                    fence_program=True, descriptors=False) == ntpath.join(host, "git.exe")
            state[0] = "literal"
            assert pathlookup.which("git.exe", path=entry, outside=fence,
                                    fence_program=True, descriptors=False) is not None
        assert pathlookup.which("git.exe", path=r"Z:\host", outside=fence,
                                fence_program=True, descriptors=False) == r"Z:\host\git.exe"
        literal_unc = r"\\literal\share\host"
        assert pathlookup.which("git.exe", path=literal_unc, outside=fence,
                                fence_program=True, descriptors=False) == ntpath.join(literal_unc, "git.exe")
        prefix = "\\\\server\\"
        unc_root = prefix + "s" * (pathlookup._MAX_FENCE_CHARS - len(prefix))
        assert pathlookup.which("git.exe", path=unc_root, outside=fence,
                                fence_program=True, descriptors=False) is None


@pytest.mark.skipif(os.name != "posix", reason="descriptor root checks require POSIX")
@pytest.mark.parametrize("phase", ["start", "reset"])
def test_descriptor_alias_roots_refuse_and_close_then_retry(tmp_path, clean_checkout_ancestors, phase):
    from conftest import symlink_or_skip
    from aegis_core import pathlookup
    if not pathlookup.descriptor_fence_supported() or not os.path.isdir("/proc/self/fd"):
        pytest.skip("descriptor counting requires procfs")
    ws = _marker(tmp_path / "ws")
    sub = ws / "sub"
    sub.mkdir()
    link = ws / "link"
    symlink_or_skip(os.sep, link, target_is_directory=True)
    original, roots = pathlookup._fd_location, []

    def location(fd):
        physical = original(fd)
        if physical == os.sep:
            roots.append(fd)
            if phase == "start" or len(roots) > 1:
                return str(sub)
        return physical

    before = len(os.listdir("/proc/self/fd"))
    pathlookup._fd_location = location
    try:
        cwd = os.sep if phase == "start" else link
        assert pathlookup.git_fence(cwd) == _volume()
    finally:
        pathlookup._fd_location = original
    assert roots
    assert len(os.listdir("/proc/self/fd")) == before
    assert pathlookup.git_fence(ws) == str(ws)
