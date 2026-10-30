"""Go cache behavior with a fake compiler at the external-process boundary."""
from __future__ import annotations

import os
import ctypes
from pathlib import Path
import stat
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import threading
import time
from types import SimpleNamespace

import pytest

from tests.conftest import symlink_or_skip


def _process_running(pid):
    if os.name == "nt":
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = (ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32)
        kernel.OpenProcess.restype = ctypes.c_void_p
        kernel.WaitForSingleObject.argtypes = (ctypes.c_void_p, ctypes.c_uint32)
        kernel.WaitForSingleObject.restype = ctypes.c_uint32
        kernel.CloseHandle.argtypes = (ctypes.c_void_p,)
        handle = kernel.OpenProcess(0x100000, False, pid)
        if not handle:
            if ctypes.get_last_error() == 87:
                return False
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            result = kernel.WaitForSingleObject(handle, 0)
            if result not in (0, 258):
                raise ctypes.WinError(ctypes.get_last_error())
            return result == 258
        finally:
            assert kernel.CloseHandle(handle)
    return _posix_process_running(pid)


def _posix_process_running(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    # A terminated orphan may remain a zombie under a container's non-reaping init.
    status = Path(f"/proc/{pid}/stat")
    try:
        return status.read_text().rsplit(")", 1)[1].split()[0] != "Z"
    except FileNotFoundError:
        # The process may have exited, or this platform may have no procfs.
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        return True


def _cleanup_child(pid):
    if _process_running(pid):
        try:
            os.kill(pid, 9)
        except ProcessLookupError:
            pass  # Exit between the liveness query and kill already satisfies cleanup.


@pytest.mark.parametrize("exited", [True, False])
def test_process_state_rechecks_a_missing_status_file(monkeypatch, exited):
    calls = []
    original = Path.read_text

    def kill(pid, sig):
        assert (pid, sig) == (987654321, 0)
        calls.append(sig)
        if exited and len(calls) > 1:
            raise ProcessLookupError("exited between process and status queries")

    def read(path, *args, **kwargs):
        if path == Path("/proc/987654321/stat"):
            raise FileNotFoundError("process exited or procfs unavailable")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(os, "kill", kill)
    monkeypatch.setattr(Path, "read_text", read)
    assert _posix_process_running(987654321) is not exited
    assert calls == [0, 0]


def test_process_status_permission_failure_is_not_treated_as_exit(monkeypatch):
    original = Path.read_text
    monkeypatch.setattr(os, "kill", lambda pid, sig: None)

    def read(path, *args, **kwargs):
        if path == Path("/proc/987654321/stat"):
            raise PermissionError("status access denied")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read)
    with pytest.raises(PermissionError, match="^status access denied$"):
        _posix_process_running(987654321)


@pytest.mark.parametrize("failure", [ProcessLookupError, PermissionError])
def test_child_cleanup_handles_only_a_process_that_already_exited(monkeypatch, failure):
    calls = []

    def kill(pid, sig):
        assert pid == 987654321
        calls.append(sig)
        if sig == 9:
            raise failure("cleanup boundary")

    monkeypatch.setattr(os, "kill", kill)
    monkeypatch.setattr(sys.modules[__name__], "_process_running", lambda pid: True)
    if failure is PermissionError:
        with pytest.raises(PermissionError, match="^cleanup boundary$"):
            _cleanup_child(987654321)
    else:
        _cleanup_child(987654321)
    assert calls[-1] == 9


@pytest.mark.parametrize("ending", ["timeout", "failure", "success"])
def test_public_build_terminates_ordinary_compiler_descendants_before_return(tmp_path, monkeypatch, ending):
    from aegis_core.ast.gobuild import GoDriverUnavailableError, prepare_go_driver

    home, workspace, tools = [tmp_path / name for name in ("home", "workspace", "tools")]
    for path in (home, workspace, tools):
        path.mkdir()
    for key in ("HOME", "USERPROFILE", "LOCALAPPDATA"):
        monkeypatch.setenv(key, str(home))
    monkeypatch.setenv("XDG_CACHE_HOME", str(home / "cache"))
    monkeypatch.setenv("PATH", str(tools))
    compiler = tools / ("go.exe" if os.name == "nt" else "go")
    compiler.write_bytes(b"trusted process-boundary fixture")
    compiler.chmod(0o755)
    pidfile = tools / "child.pid"
    script = tools / "compiler.py"
    script.write_text(
        "import os, pathlib, subprocess, sys, time\n"
        "if sys.argv[1] == 'env':\n"
        " print('go1.22.2\\nlinux\\namd64'); raise SystemExit(0)\n"
        "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'], "
        "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
        f"pathlib.Path({str(pidfile)!r}).write_text(str(child.pid))\n"
        + ("time.sleep(30)\n" if ending == "timeout" else
           "raise SystemExit('fixture build failed')\n" if ending == "failure" else
           "out = pathlib.Path(sys.argv[sys.argv.index('-o') + 1]); out.write_bytes(b'complete'); out.chmod(0o700)\n"),
        encoding="utf-8")
    real_popen = subprocess.Popen

    def spawn(argv, *args, **options):
        if str(argv[0]) == str(compiler):
            argv = [sys.executable, str(script), *argv[1:]]
        return real_popen(argv, *args, **options)

    monkeypatch.setattr(subprocess, "Popen", spawn)
    try:
        if ending == "success":
            assert prepare_go_driver(workspace, timeout=0.5).read_bytes() == b"complete"
        else:
            message = "go build timed out after 0.5s" if ending == "timeout" else "fixture build failed"
            with pytest.raises(GoDriverUnavailableError, match=message) as error:
                prepare_go_driver(workspace, timeout=0.5)
            assert error.value.reason == "build_failed"
        child_pid = int(pidfile.read_text())
        deadline = time.monotonic() + 2
        while _process_running(child_pid) and time.monotonic() < deadline:
            time.sleep(0.01)
        assert not _process_running(child_pid), "compiler descendant survived the public build call"
        assert not list(home.rglob(".go-build-*"))
    finally:
        if pidfile.exists():
            child_pid = int(pidfile.read_text())
            _cleanup_child(child_pid)


@pytest.fixture
def compiler(tmp_path, monkeypatch):
    home, workspace, tools = [tmp_path / n for n in ("home", "workspace", "tools")]
    for directory in (home, workspace, tools):
        directory.mkdir()
    executable = tools / ("go.exe" if os.name == "nt" else "go")
    executable.write_text("fake compiler: never execute this file", encoding="utf-8")
    executable.chmod(0o755)
    for key in ("HOME", "USERPROFILE", "LOCALAPPDATA"):
        monkeypatch.setenv(key, str(home))
    monkeypatch.setenv("XDG_CACHE_HOME", str(home / "cache"))
    monkeypatch.setenv("PATH", str(tools))
    monkeypatch.setenv("GOCACHE", str(home / "go-cache"))
    cache = (home / "aegis/Cache/drivers" if sys.platform == "win32" else
             home / "Library/Caches/aegis/drivers" if sys.platform == "darwin" else
             home / "cache/aegis/drivers")
    state = SimpleNamespace(home=home, workspace=workspace, executable=executable, cache=cache,
                            calls=[], version="go1.21.0", goos="linux", arch="amd64",
                            fail=None, timed_out=False, copied=None, private_mode=None,
                            timeout_operation=None, no_binary=False)
    real_popen = subprocess.Popen

    def popen(argv, **kwargs):
        options = dict(kwargs)
        state.calls.append((list(argv), options))
        if state.fail == argv[1]:
            code = "raise SystemExit('fake compiler failure')"
        elif argv[1] == "env":
            code = f"print({(state.version + chr(10) + state.goos + chr(10) + state.arch)!r})"
        else:
            directory = Path(kwargs["cwd"])
            state.copied = {name: (directory / name).read_bytes() for name in ("go_ast.go", "go.mod")}
            state.private_mode = stat.S_IMODE(directory.stat().st_mode)
            output = Path(argv[argv.index("-o") + 1])
            code = ("pass" if state.no_binary else
                    f"from pathlib import Path; p=Path({str(output)!r}); p.write_bytes(b'complete fake driver'); p.chmod(0o755)")
        proc = real_popen([sys.executable, "-c", code], **kwargs)
        communicate = proc.communicate

        def communicate_with_deadline(*args, **kw):
            options["timeout"] = kw.get("timeout")
            if state.timed_out or state.timeout_operation == argv[1]:
                raise subprocess.TimeoutExpired(argv, kw["timeout"])
            return communicate(*args, **kw)

        proc.communicate = communicate_with_deadline
        return proc

    monkeypatch.setattr(subprocess, "Popen", popen)
    return state


def test_prepare_builds_complete_binary_once_and_reuses_it(compiler):
    from aegis_core.ast.gobuild import prepare_go_driver

    first = prepare_go_driver(compiler.workspace)
    second = prepare_go_driver(compiler.workspace)

    assert first == second
    assert first.is_absolute()
    assert first.read_bytes() == b"complete fake driver"
    assert os.access(first, os.X_OK)
    assert [argv[1] for argv, _ in compiler.calls].count("build") == 1
    assert compiler.workspace not in first.parents


def test_prepare_publishes_complete_binary_when_flush_requires_write_access(compiler, monkeypatch):
    from aegis_core.ast.gobuild import prepare_go_driver

    fsync = os.fsync

    def flush_writable_file(fd):
        if stat.S_ISREG(os.fstat(fd).st_mode):
            # Windows cannot flush a read-only file handle. A zero-byte write
            # enforces the same access requirement without changing its bytes.
            os.write(fd, b"")
        fsync(fd)

    monkeypatch.setattr(os, "fsync", flush_writable_file)
    binary = prepare_go_driver(compiler.workspace)

    assert binary.read_bytes() == b"complete fake driver"
    assert prepare_go_driver(compiler.workspace) == binary
    assert not list(compiler.cache.glob(".go-build-*"))


def test_build_is_private_offline_and_retains_only_safe_environment(compiler, monkeypatch):
    from aegis_core.ast.gobuild import prepare_go_driver

    for name in ("GOTOOLCHAIN", "GOPROXY", "GOWORK", "GOFLAGS", "GOENV", "GO111MODULE", "CGO_ENABLED"):
        monkeypatch.setenv(name, "unsafe inherited setting")
    for name in ("GOROOT", "GOPATH", "GOCACHEPROG", "GOEXPERIMENT", "UNRELATED_USER_VALUE"):
        monkeypatch.setenv(name, "must not reach build")
    monkeypatch.setenv("PATH", os.pathsep.join(["", ".", str(compiler.workspace), str(compiler.executable.parent)]))

    binary = prepare_go_driver(compiler.workspace)

    assert binary.parent == compiler.cache
    for argv, options in compiler.calls:
        assert argv[0] == str(compiler.executable)
        cwd = Path(options["cwd"])
        assert compiler.cache in cwd.parents
        assert compiler.workspace not in cwd.parents
        assert options["stdin"] == subprocess.DEVNULL
        env = options["env"]
        assert {name: env[name] for name in ("GOTOOLCHAIN", "GOPROXY", "GOWORK", "GOFLAGS", "GOENV",
                                            "GO111MODULE", "CGO_ENABLED")} == {
            "GOTOOLCHAIN": "local", "GOPROXY": "off", "GOWORK": "off", "GOFLAGS": "",
            "GOENV": "off", "GO111MODULE": "on", "CGO_ENABLED": "0"}
        assert env["GOCACHE"] == str(compiler.home / "go-cache")
        assert env["PATH"] == str(compiler.executable.parent)
        assert not {"GOROOT", "GOPATH", "GOCACHEPROG", "GOEXPERIMENT", "UNRELATED_USER_VALUE"} & env.keys()
    build, options = next((a, o) for a, o in compiler.calls if a[1] == "build")
    assert build[1:3] == ["build", "-trimpath"]
    assert build[-1] == "."
    assert options["timeout"] == 120.0
    assert not list(compiler.cache.glob(".go-build-*"))
    templates = Path(__file__).resolve().parents[3] / "aegis_core/ast/drivers/templates"
    assert compiler.copied == {name: (templates / name).read_bytes() for name in ("go_ast.go", "go.mod")}
    if os.name == "posix":
        assert stat.S_IMODE(binary.stat().st_mode) == 0o700
        assert compiler.private_mode == 0o700


@pytest.mark.parametrize("field,value", [("version", "go1.22.1"), ("goos", "darwin"), ("arch", "arm64")])
def test_toolchain_identity_changes_the_cache_key(compiler, field, value):
    from aegis_core.ast.gobuild import prepare_go_driver

    first = prepare_go_driver(compiler.workspace)
    setattr(compiler, field, value)
    second = prepare_go_driver(compiler.workspace)

    assert first != second
    assert first.read_bytes() == second.read_bytes() == b"complete fake driver"
    assert [a[1] for a, _ in compiler.calls].count("build") == 2


@pytest.mark.parametrize("filename", ["go_ast.go", "go.mod"])
def test_packaged_source_and_module_bytes_both_bind_the_key(compiler, monkeypatch, filename):
    from aegis_core.ast.gobuild import prepare_go_driver

    first = prepare_go_driver(compiler.workspace)
    read = Path.read_bytes

    def changed(path):
        data = read(path)
        return data + b"\n// package revision\n" if path.name == filename else data

    monkeypatch.setattr(Path, "read_bytes", changed)
    second = prepare_go_driver(compiler.workspace)

    assert first != second
    assert [a[1] for a, _ in compiler.calls].count("build") == 2


def test_missing_go_is_a_reasoned_unavailable_result(compiler, monkeypatch):
    from aegis_core.ast.gobuild import GoDriverUnavailableError, prepare_go_driver

    monkeypatch.setenv("PATH", "")
    with pytest.raises(GoDriverUnavailableError, match="driver_unavailable:go_missing") as error:
        prepare_go_driver(compiler.workspace)
    assert error.value.reason == "go_missing"
    assert "outside the workspace" in error.value.detail
    assert compiler.calls == []


@pytest.mark.parametrize("version", ["go1.20.9", "go1.9.7", "go1.21garbage"])
def test_old_or_unrecognized_go_never_builds(compiler, version):
    from aegis_core.ast.gobuild import GoDriverUnavailableError, prepare_go_driver

    compiler.version = version
    with pytest.raises(GoDriverUnavailableError, match="go >=1.21 required") as error:
        prepare_go_driver(compiler.workspace)
    assert error.value.reason == "go_too_old"
    assert [a[1] for a, _ in compiler.calls] == ["env"]


def test_malformed_toolchain_identity_fails_closed(compiler):
    from aegis_core.ast.gobuild import GoDriverUnavailableError, prepare_go_driver

    compiler.goos = "../escape"
    with pytest.raises(GoDriverUnavailableError, match="invalid GOVERSION/GOOS/GOARCH") as error:
        prepare_go_driver(compiler.workspace)
    assert error.value.reason == "build_failed"
    assert not list(compiler.cache.glob("go_ast-*"))


@pytest.mark.parametrize("operation", ["env", "build"])
def test_compiler_failure_preserves_the_reason_and_publishes_nothing(compiler, operation):
    from aegis_core.ast.gobuild import GoDriverUnavailableError, prepare_go_driver

    compiler.fail = operation
    with pytest.raises(GoDriverUnavailableError, match="fake compiler failure") as error:
        prepare_go_driver(compiler.workspace)
    assert error.value.reason == "build_failed"
    assert not [p for p in compiler.cache.glob("go_ast-*") if p.suffix != ".lock"]


def test_probe_timeout_fails_closed(compiler):
    from aegis_core.ast.gobuild import GoDriverUnavailableError, prepare_go_driver

    compiler.timed_out = True
    with pytest.raises(GoDriverUnavailableError, match="go env timed out after 3s"):
        prepare_go_driver(compiler.workspace)


def test_build_timeout_has_its_own_deadline(compiler, monkeypatch):
    from aegis_core.ast.gobuild import GoDriverUnavailableError, prepare_go_driver

    compiler.timeout_operation = "build"
    with pytest.raises(GoDriverUnavailableError, match="go build timed out after 0.25s"):
        prepare_go_driver(compiler.workspace, timeout=0.25)
    assert compiler.calls[-1][1]["timeout"] == 0.25
    assert not [p for p in compiler.cache.glob("go_ast-*") if p.suffix != ".lock"]


def test_cache_inside_workspace_is_refused_before_build(compiler, monkeypatch):
    from aegis_core.ast.gobuild import GoDriverUnavailableError, prepare_go_driver

    for key in ("HOME", "USERPROFILE", "LOCALAPPDATA", "XDG_CACHE_HOME"):
        monkeypatch.setenv(key, str(compiler.workspace))
    with pytest.raises(GoDriverUnavailableError, match="driver_unavailable:cache_unsafe"):
        prepare_go_driver(compiler.workspace)
    assert compiler.calls == []


def test_symlinked_cache_ancestor_is_refused(compiler):
    from aegis_core.ast.gobuild import GoDriverUnavailableError, prepare_go_driver

    ancestor = compiler.cache.parent
    ancestor.parent.mkdir(parents=True, exist_ok=True)
    destination = compiler.home / "redirect"
    destination.mkdir()
    symlink_or_skip(destination, ancestor, target_is_directory=True)
    with pytest.raises(GoDriverUnavailableError, match="symlink or reparse point"):
        prepare_go_driver(compiler.workspace)
    assert compiler.calls == []


def test_reparse_point_cache_ancestor_is_refused(compiler, monkeypatch):
    from aegis_core.ast.gobuild import GoDriverUnavailableError, prepare_go_driver

    compiler.cache.mkdir(parents=True)
    lstat = Path.lstat

    def reparse(path):
        info = lstat(path)
        return SimpleNamespace(st_mode=info.st_mode, st_file_attributes=0x400) if path == compiler.cache.parent else info

    monkeypatch.setattr(Path, "lstat", reparse)
    with pytest.raises(GoDriverUnavailableError, match="symlink or reparse point"):
        prepare_go_driver(compiler.workspace)
    assert compiler.calls == []


def test_cached_binary_symlink_is_refused(compiler):
    from aegis_core.ast.gobuild import GoDriverUnavailableError, prepare_go_driver

    binary = prepare_go_driver(compiler.workspace)
    destination = binary.with_name("original")
    binary.rename(destination)
    symlink_or_skip(destination, binary)
    with pytest.raises(GoDriverUnavailableError, match="driver_unavailable:cache_unsafe"):
        prepare_go_driver(compiler.workspace)
    assert [a[1] for a, _ in compiler.calls].count("build") == 1


def test_compiler_symlink_back_into_workspace_is_not_run(compiler):
    from aegis_core.ast.gobuild import GoDriverUnavailableError, prepare_go_driver

    destination = compiler.workspace / compiler.executable.name
    compiler.executable.rename(destination)
    symlink_or_skip(destination, compiler.executable)
    with pytest.raises(GoDriverUnavailableError, match="driver_unavailable:go_missing"):
        prepare_go_driver(compiler.workspace)
    assert compiler.calls == []


def test_publication_failure_never_leaves_a_partial_binary(compiler, monkeypatch):
    from aegis_core.ast.gobuild import GoDriverUnavailableError, prepare_go_driver

    replace = os.replace

    def blocked(source, destination):
        if Path(destination).parent != compiler.cache:
            return replace(source, destination)
        assert Path(source).read_bytes() == b"complete fake driver"
        assert not Path(destination).exists()
        raise PermissionError("publication denied")

    monkeypatch.setattr(os, "replace", blocked)
    with pytest.raises(GoDriverUnavailableError, match="publication denied"):
        prepare_go_driver(compiler.workspace)
    assert not [p for p in compiler.cache.glob("go_ast-*") if p.suffix != ".lock"]
    assert not list(compiler.cache.glob(".go-build-*"))


def test_two_callers_publish_and_use_one_complete_binary(compiler, monkeypatch):
    from aegis_core.ast.gobuild import prepare_go_driver

    entered, release = threading.Event(), threading.Event()
    popen = subprocess.Popen

    def delayed(argv, **kwargs):
        if argv[1] == "build":
            entered.set()
            assert release.wait(2), "test did not release the fake compiler"
        return popen(argv, **kwargs)

    monkeypatch.setattr(subprocess, "Popen", delayed)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(prepare_go_driver, compiler.workspace)
        assert entered.wait(2), "fake compiler never started"
        second = pool.submit(prepare_go_driver, compiler.workspace)
        release.set()
        paths = [first.result(timeout=3), second.result(timeout=3)]
    assert paths[0] == paths[1]
    assert paths[0].read_bytes() == b"complete fake driver"
    assert [a[1] for a, _ in compiler.calls].count("build") == 1


def test_lock_failure_is_reasoned_without_publishing(compiler, monkeypatch):
    from aegis_core.ast import gobuild
    from aegis_core.errors import LockTimeoutError

    @contextmanager
    def held(path, timeout):
        assert timeout == 123.0
        raise LockTimeoutError("another builder holds the lock")
        yield

    monkeypatch.setattr(gobuild, "file_lock", held)
    with pytest.raises(gobuild.GoDriverUnavailableError, match="another builder holds the lock") as error:
        gobuild.prepare_go_driver(compiler.workspace)
    assert error.value.reason == "build_failed"
    assert [a[1] for a, _ in compiler.calls] == ["env"]


def test_cache_lock_symlink_is_refused_before_another_build(compiler):
    from aegis_core.ast.gobuild import GoDriverUnavailableError, prepare_go_driver

    binary = prepare_go_driver(compiler.workspace)
    lock = next(compiler.cache.glob("*.lock"))
    target = compiler.home / "lock-target"
    target.write_text("untouched", encoding="utf-8")
    binary.unlink()
    lock.unlink()
    symlink_or_skip(target, lock)

    with pytest.raises(GoDriverUnavailableError, match="driver_unavailable:cache_unsafe"):
        prepare_go_driver(compiler.workspace)
    assert target.read_text() == "untouched"
    assert [a[1] for a, _ in compiler.calls].count("build") == 1


def test_directory_at_cached_binary_is_refused(compiler):
    from aegis_core.ast.gobuild import GoDriverUnavailableError, prepare_go_driver

    binary = prepare_go_driver(compiler.workspace)
    binary.unlink()
    binary.mkdir()
    with pytest.raises(GoDriverUnavailableError, match="unsafe file type") as error:
        prepare_go_driver(compiler.workspace)
    assert error.value.reason == "cache_unsafe"
    assert [a[1] for a, _ in compiler.calls].count("build") == 1


def test_missing_packaged_source_fails_without_running_compiler(compiler, monkeypatch):
    from aegis_core.ast.gobuild import GoDriverUnavailableError, prepare_go_driver

    read = Path.read_bytes

    def missing(path):
        if path.name == "go_ast.go":
            raise FileNotFoundError("packaged Go source missing")
        return read(path)

    monkeypatch.setattr(Path, "read_bytes", missing)
    with pytest.raises(GoDriverUnavailableError, match="packaged Go source missing") as error:
        prepare_go_driver(compiler.workspace)
    assert error.value.reason == "build_failed"
    assert compiler.calls == []


def test_success_exit_without_executable_fails_closed(compiler, monkeypatch):
    from aegis_core.ast.gobuild import GoDriverUnavailableError, prepare_go_driver

    compiler.no_binary = True
    with pytest.raises(GoDriverUnavailableError, match="did not produce a complete executable"):
        prepare_go_driver(compiler.workspace)
    assert not [p for p in compiler.cache.glob("go_ast-*") if p.suffix != ".lock"]


def test_cold_inspection_reports_metadata_and_miss_without_creating_cache_state(compiler):
    from aegis_core.ast.gobuild import inspect_go_driver

    before = sorted(p.relative_to(compiler.home) for p in compiler.home.rglob("*"))
    status = inspect_go_driver(compiler.workspace)

    assert status.compiler == compiler.executable
    assert (status.goversion, status.goos, status.goarch) == ("go1.21.0", "linux", "amd64")
    assert status.binary.parent == compiler.cache
    assert status.cache_hit is False
    assert not status.binary.exists()
    assert before == sorted(p.relative_to(compiler.home) for p in compiler.home.rglob("*"))
    assert [argv[1:] for argv, _ in compiler.calls] == [["env", "GOVERSION", "GOOS", "GOARCH"]]
    assert compiler.calls[0][1]["env"]["GO111MODULE"] == "off"


@pytest.mark.parametrize("changed", ["version", "goos", "arch", "go_ast.go", "go.mod"])
def test_inspection_and_preparation_share_every_cache_key_input(compiler, monkeypatch, changed):
    from aegis_core.ast.gobuild import inspect_go_driver, prepare_go_driver

    original = inspect_go_driver(compiler.workspace)
    if changed in ("go_ast.go", "go.mod"):
        read = Path.read_bytes
        monkeypatch.setattr(Path, "read_bytes", lambda p: read(p) +
                            (b"\n// revision\n" if p.name == changed else b""))
    else:
        setattr(compiler, changed, {"version": "go1.22.1", "goos": "darwin", "arch": "arm64"}[changed])
    cold = inspect_go_driver(compiler.workspace)
    binary = prepare_go_driver(compiler.workspace)
    warm = inspect_go_driver(compiler.workspace)

    assert original.binary != cold.binary
    assert cold.binary == binary == warm.binary
    assert cold.cache_hit is False and warm.cache_hit is True
    assert [argv[1] for argv, _ in compiler.calls].count("build") == 1
    assert [options["env"]["GO111MODULE"] for argv, options in compiler.calls if argv[1] == "build"] == ["on"]


@pytest.mark.parametrize("problem,reason,message", [
    ("missing", "go_missing", "go was not found on PATH outside the workspace"),
    ("old", "go_too_old", "go >=1.21 required; found go1.20.9"),
    ("probe", "build_failed", "go env failed: fake compiler failure"),
    ("timeout", "build_failed", "go env timed out after 3s"),
    ("unsafe", "cache_unsafe", "cache path must be absolute and outside the workspace"),
])
def test_inspection_failures_preserve_reasons_and_create_no_cache_state(compiler, monkeypatch, problem, reason, message):
    from aegis_core.ast.gobuild import GoDriverUnavailableError, inspect_go_driver

    if problem == "missing":
        monkeypatch.setenv("PATH", "")
    elif problem == "old":
        compiler.version = "go1.20.9"
    elif problem == "probe":
        compiler.fail = "env"
    elif problem == "timeout":
        compiler.timed_out = True
    else:
        for key in ("HOME", "USERPROFILE", "LOCALAPPDATA", "XDG_CACHE_HOME"):
            monkeypatch.setenv(key, str(compiler.workspace))
    before = sorted(p.relative_to(compiler.home) for p in compiler.home.rglob("*"))
    with pytest.raises(GoDriverUnavailableError) as error:
        inspect_go_driver(compiler.workspace)
    assert error.value.reason == reason
    assert message in error.value.detail
    assert before == sorted(p.relative_to(compiler.home) for p in compiler.home.rglob("*"))
    assert all(argv[1] == "env" for argv, _ in compiler.calls)


def test_inspection_ignores_parent_module_repository_and_user_toolchain_pins(compiler, monkeypatch):
    from aegis_core.ast.gobuild import inspect_go_driver

    pin = "module example.test/pin\n\ngo 1.99\ntoolchain go1.99.0\n"
    for directory in (compiler.home, compiler.workspace):
        (directory / "go.mod").write_text(pin, encoding="utf-8")
        (directory / "go.work").write_text("go 1.99\ntoolchain go1.99.0\n", encoding="utf-8")
    for key in ("GOTOOLCHAIN", "GOPROXY", "GOWORK", "GOENV", "GOFLAGS", "GO111MODULE"):
        monkeypatch.setenv(key, "unsafe inherited pin")
    popen = subprocess.Popen

    def metadata(argv, **options):
        assert argv[1:] == ["env", "GOVERSION", "GOOS", "GOARCH"]
        env = options["env"]
        assert {key: env[key] for key in ("GO111MODULE", "GOTOOLCHAIN", "GOPROXY", "GOWORK", "GOENV", "GOFLAGS")} == {
            "GO111MODULE": "off", "GOTOOLCHAIN": "local", "GOPROXY": "off",
            "GOWORK": "off", "GOENV": "off", "GOFLAGS": ""}
        return popen(argv, **options)

    monkeypatch.setattr(subprocess, "Popen", metadata)
    status = inspect_go_driver(compiler.workspace)
    assert status.goversion == "go1.21.0"
    assert status.cache_hit is False
    assert (compiler.home / "go.mod").read_text() == pin
    assert not compiler.cache.exists()


@pytest.mark.parametrize("entry", ["binary", "lock"])
def test_inspection_refuses_unsafe_existing_cache_entries_without_repairing_them(compiler, entry):
    from aegis_core.ast.gobuild import GoDriverUnavailableError, inspect_go_driver, prepare_go_driver

    binary = prepare_go_driver(compiler.workspace)
    destination = compiler.home / "untouched"
    destination.write_text("untouched", encoding="utf-8")
    victim = binary if entry == "binary" else next(compiler.cache.glob("*.lock"))
    binary.unlink()
    if victim != binary:
        victim.unlink()
    symlink_or_skip(destination, victim)
    with pytest.raises(GoDriverUnavailableError) as error:
        inspect_go_driver(compiler.workspace)
    assert error.value.reason == "cache_unsafe"
    assert victim.is_symlink()
    assert destination.read_text() == "untouched"
    assert [argv[1] for argv, _ in compiler.calls].count("build") == 1


def test_preparation_rechecks_cache_safety_after_a_successful_inspection(compiler):
    from aegis_core.ast.gobuild import GoDriverUnavailableError, inspect_go_driver, prepare_go_driver

    assert inspect_go_driver(compiler.workspace).cache_hit is False
    ancestor = compiler.cache.parent
    ancestor.parent.mkdir(parents=True, exist_ok=True)
    destination = compiler.home / "redirect"
    destination.mkdir()
    symlink_or_skip(destination, ancestor, target_is_directory=True)
    with pytest.raises(GoDriverUnavailableError) as error:
        prepare_go_driver(compiler.workspace)
    assert error.value.reason == "cache_unsafe"
    assert [argv[1] for argv, _ in compiler.calls] == ["env"]


@pytest.mark.parametrize("operation", ["inspect_go_driver", "prepare_go_driver"])
@pytest.mark.parametrize("layout", ["directory", "directory_link", "source_link", "module_link"])
def test_packaged_sources_inside_workspace_are_refused_before_probing_or_writing(
        compiler, monkeypatch, operation, layout):
    from aegis_core.ast import gobuild

    inside = compiler.workspace / ".venv" / "templates"
    inside.mkdir(parents=True)
    for name in ("go_ast.go", "go.mod"):
        (inside / name).write_bytes((gobuild._TEMPLATES / name).read_bytes())
    templates = inside
    if layout != "directory":
        templates = compiler.home / "installed" / "templates"
        templates.parent.mkdir(parents=True)
        if layout == "directory_link":
            symlink_or_skip(inside, templates, target_is_directory=True)
        else:
            templates.mkdir()
            linked = "go_ast.go" if layout == "source_link" else "go.mod"
            for name in ("go_ast.go", "go.mod"):
                if name == linked:
                    symlink_or_skip(inside / name, templates / name)
                else:
                    (templates / name).write_bytes((inside / name).read_bytes())
    monkeypatch.setattr(gobuild, "_TEMPLATES", templates)
    before = sorted(path.relative_to(compiler.home) for path in compiler.home.rglob("*"))

    with pytest.raises(gobuild.GoDriverUnavailableError,
                       match="packaged Go source is installed inside the workspace") as error:
        getattr(gobuild, operation)(compiler.workspace)

    assert error.value.reason == "build_failed"
    assert compiler.calls == []
    assert not compiler.cache.exists()
    assert before == sorted(path.relative_to(compiler.home) for path in compiler.home.rglob("*"))


def test_inspection_refuses_a_cache_with_no_existing_ancestor(compiler, monkeypatch):
    from aegis_core.ast.gobuild import GoDriverUnavailableError, inspect_go_driver

    visited = set()

    def missing_directory(path):
        assert path not in visited, "metadata inspection repeated a missing filesystem root"
        visited.add(path)
        return False

    # A missing Windows drive has no existing ancestor for metadata's cwd.
    monkeypatch.setattr(Path, "is_dir", missing_directory)
    with pytest.raises(GoDriverUnavailableError, match="no existing directory for the Go metadata probe") as error:
        inspect_go_driver(compiler.workspace)
    assert error.value.reason == "cache_unsafe"
    assert compiler.calls == []


@pytest.mark.parametrize("cancel", [False, True])
def test_compiler_communication_error_or_cancellation_reaps_root_before_removing_directory(compiler, monkeypatch, cancel):
    from aegis_core.ast.gobuild import GoDriverUnavailableError, prepare_go_driver

    popen, processes = subprocess.Popen, []

    def interrupted(argv, **options):
        proc = popen(argv, **options)
        if argv[1] == "build":
            processes.append(proc)

            def communicate(**kw):
                raise KeyboardInterrupt("fixture cancellation") if cancel else OSError("fixture pipe error")

            proc.communicate = communicate
        return proc

    monkeypatch.setattr(subprocess, "Popen", interrupted)
    error_type = KeyboardInterrupt if cancel else GoDriverUnavailableError
    with pytest.raises(error_type, match="fixture cancellation" if cancel else "fixture pipe error"):
        prepare_go_driver(compiler.workspace)
    assert processes and all(proc.poll() is not None for proc in processes)
    assert all(proc.stdout.closed and proc.stderr.closed for proc in processes)
    assert not list(compiler.cache.glob(".go-build-*"))


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-group failure boundary")
def test_failed_tree_cleanup_preserves_original_diagnostic_and_private_directory(compiler, monkeypatch):
    from aegis_core.ast.gobuild import GoDriverUnavailableError, prepare_go_driver

    compiler.fail = "build"
    killpg = os.killpg

    def denied(pid, signal):
        if compiler.calls[-1][0][1] == "build":
            raise PermissionError("fixture group cleanup denied")
        return killpg(pid, signal)

    monkeypatch.setattr(os, "killpg", denied)
    with pytest.raises(GoDriverUnavailableError, match="fake compiler failure.*cleanup failed:.*cleanup denied") as error:
        prepare_go_driver(compiler.workspace)
    assert error.value.reason == "build_failed"
    private = list(compiler.cache.glob(".go-build-*"))
    assert len(private) == 1 and (private[0] / "go_ast.go").is_file()
    assert not [p for p in compiler.cache.glob("go_ast-*") if p.suffix != ".lock"]


@pytest.mark.skipif(os.name != "nt", reason="native Windows real Go compiler lifecycle")
def test_native_windows_real_go_success_accepts_waited_compiler_children(tmp_path, monkeypatch):
    from aegis_core.ast.gobuild import prepare_go_driver
    from aegis_core.pathlookup import which

    home, workspace = tmp_path / "home", tmp_path / "workspace"
    home.mkdir()
    workspace.mkdir()
    if which("go", outside=workspace) is None:
        pytest.skip("native Windows integration requires installed Go >=1.21")
    for name in ("HOME", "USERPROFILE", "LOCALAPPDATA"):
        monkeypatch.setenv(name, str(home))
    binary = prepare_go_driver(workspace)
    assert binary.is_file() and binary.stat().st_size > 0
    assert prepare_go_driver(workspace) == binary
    assert not list(home.rglob(".go-build-*"))
