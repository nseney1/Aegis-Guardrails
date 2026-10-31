"""Build Aegis's stdlib-only Go parser into a confined, atomic user cache."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile

from aegis_core.atomicio import fsync_dir
from aegis_core.errors import AegisError, LockTimeoutError, PathTraversalError
from aegis_core.pathlookup import which
from aegis_core.primitives import is_within, key_within
from aegis_core.storage import atomic_write_bytes, file_lock

__all__ = ["GoDriverStatus", "GoDriverUnavailableError", "inspect_go_driver", "prepare_go_driver"]

_TEMPLATES = Path(__file__).resolve().parent / "drivers" / "templates"
_CONTROLS = {"GOTOOLCHAIN": "local", "GOPROXY": "off", "GOWORK": "off", "GOFLAGS": "",
             "GOENV": "off", "GO111MODULE": "on", "CGO_ENABLED": "0"}
_ENV_KEEP = frozenset({"HOME", "USERPROFILE", "SYSTEMROOT", "WINDIR", "TEMP", "TMP",
                       "TMPDIR", "LOCALAPPDATA", "APPDATA", "GOCACHE"})


class GoDriverUnavailableError(AegisError):
    """The configured packaged driver cannot be prepared safely on this host."""

    def __init__(self, reason: str, detail: str):
        super().__init__(f"driver_unavailable:{reason}: {detail}", code="GO_DRIVER_UNAVAILABLE",
                         reason=reason, detail=detail)


class _GoCleanupFailure(GoDriverUnavailableError):
    """Keep the private directory when process termination cannot be established."""


@dataclass(frozen=True)
class GoDriverStatus:
    compiler: Path
    goversion: str
    goos: str
    goarch: str
    binary: Path
    cache_hit: bool


def _workspace_controlled(path: Path, workspace: Path) -> bool:
    """Refuse both repository-written paths and paths resolving into its tree."""
    return is_within(path, workspace, unresolvable=True) or key_within(
        os.path.normcase(os.path.abspath(path)), os.path.normcase(os.path.abspath(workspace)))


def _packaged_sources(workspace: Path) -> tuple[bytes, bytes]:
    paths = [_TEMPLATES / name for name in ("go_ast.go", "go.mod")]
    if any(_workspace_controlled(path, workspace) for path in paths):
        raise GoDriverUnavailableError(
            "build_failed",
            "packaged Go source is installed inside the workspace; install aegis outside it")
    return paths[0].read_bytes(), paths[1].read_bytes()


def _safe_path(path: Path, workspace: Path, *, directory: bool = False) -> None:
    """Check the written ancestor chain, before resolving away links or junctions."""
    if not path.is_absolute() or _workspace_controlled(path, workspace):
        raise GoDriverUnavailableError("cache_unsafe", f"cache path must be absolute and outside the workspace: {path}")
    for component in (*reversed(path.parents), path):
        try:
            info = component.lstat()
        except FileNotFoundError:
            continue
        reparse = getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        if stat.S_ISLNK(info.st_mode) or reparse:
            raise GoDriverUnavailableError("cache_unsafe", f"cache component is a symlink or reparse point: {component}")
        expected_dir = component != path or directory
        if not (stat.S_ISDIR(info.st_mode) if expected_dir else stat.S_ISREG(info.st_mode)):
            raise GoDriverUnavailableError("cache_unsafe", f"cache component has an unsafe file type: {component}")


def _cache_directory(workspace: Path, *, create: bool = True) -> Path:
    home = Path.home()
    if sys.platform == "win32":
        cache = Path(os.environ.get("LOCALAPPDATA", str(home / "AppData" / "Local"))) / "aegis" / "Cache" / "drivers"
    elif sys.platform == "darwin":
        cache = home / "Library" / "Caches" / "aegis" / "drivers"
    else:
        cache = Path(os.environ.get("XDG_CACHE_HOME", str(home / ".cache"))) / "aegis" / "drivers"
    _safe_path(cache, workspace, directory=True)
    if create:
        cache.mkdir(parents=True, exist_ok=True, mode=0o700)
        _safe_path(cache, workspace, directory=True)
    return cache


def _environment(workspace: Path) -> dict[str, str]:
    env = {key: value for key, value in os.environ.items() if key.upper() in _ENV_KEEP}
    entries = [entry for entry in os.environ.get("PATH", os.defpath).split(os.pathsep)
               if entry and os.path.isabs(entry) and not _workspace_controlled(Path(entry), workspace)]
    env["PATH"] = os.pathsep.join(entries)
    env.update(_CONTROLS)
    return env


def _run(argv: list[str], cwd: Path, env: dict[str, str], timeout: float) -> str:
    proc, job, original = None, None, None
    try:
        if os.name == "nt":
            from aegis_core.ast.windows_job import CREATE_SUSPENDED, WindowsJob

            job = WindowsJob()
            flags = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP | CREATE_SUSPENDED}
        else:
            flags = {"start_new_session": True}
        proc = subprocess.Popen(argv, cwd=str(cwd), env=env, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                encoding="utf-8", errors="replace", **flags)
        if job is not None:
            job.assign_and_resume(proc.pid)
        stdout, stderr = proc.communicate(timeout=timeout)
        if proc.returncode:
            detail = (stderr or stdout or f"exit {proc.returncode}").strip()[:1000]
            raise GoDriverUnavailableError("build_failed", f"go {argv[1]} failed: {detail}")
        return stdout
    except subprocess.TimeoutExpired as exc:
        original = GoDriverUnavailableError("build_failed", f"go {argv[1]} timed out after {timeout:g}s")
        raise original from exc
    except OSError as exc:
        original = GoDriverUnavailableError("build_failed", f"cannot execute go {argv[1]}: {exc}")
        raise original from exc
    except BaseException as exc:
        original = exc
        raise
    finally:
        failures = []
        if proc is not None:
            try:
                if job is not None:
                    if original is None and proc.returncode == 0:
                        job.terminate_completed_go_compiler_and_wait(proc)
                    else:
                        job.terminate_and_wait()
                else:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
            except (OSError, subprocess.SubprocessError) as exc:
                failures.append(exc)
            try:
                if proc.poll() is None:
                    proc.kill()
                proc.wait(timeout=3)
            except (OSError, subprocess.SubprocessError) as exc:
                failures.append(exc)
        if job is not None:
            try:
                job.close()
            except OSError as exc:
                failures.append(exc)
        if proc is not None:
            for stream in (proc.stdout, proc.stderr):
                try:
                    if failures:
                        # A failed OS termination may leave Windows communicate readers blocked.
                        stream.buffer.raw.close()
                    else:
                        stream.close()
                except (OSError, ValueError) as exc:
                    failures.append(exc)
        if failures:
            prior = f"{type(original).__name__}: {original}; " if original is not None else ""
            detail = "; ".join(f"{type(exc).__name__}: {exc}" for exc in failures)
            raise _GoCleanupFailure("build_failed", f"{prior}go {argv[1]} cleanup failed: {detail}") from original or failures[0]


def _toolchain(compiler: str, cwd: Path, env: dict[str, str]) -> bytes:
    output = _run([compiler, "env", "GOVERSION", "GOOS", "GOARCH"], cwd, env, 3.0)
    lines = output.strip().splitlines()
    if len(lines) != 3 or not all(re.fullmatch(r"[A-Za-z0-9.+_-]+", value) for value in lines):
        raise GoDriverUnavailableError("build_failed", "go env returned invalid GOVERSION/GOOS/GOARCH")
    version = re.fullmatch(r"go(\d+)\.(\d+)(?:\.\d+)?(?:beta\d+|rc\d+)?", lines[0])
    if version is None or tuple(map(int, version.groups())) < (1, 21):
        raise GoDriverUnavailableError("go_too_old", f"go >=1.21 required; found {lines[0]}")
    return "\n".join(lines).encode("ascii")


def _cached(binary: Path, workspace: Path) -> bool:
    _safe_path(binary, workspace)
    return binary.is_file() and binary.stat().st_size > 0 and (os.name == "nt" or os.access(binary, os.X_OK))


def _compiler(workspace: Path) -> str:
    compiler = which("go", outside=workspace)
    if compiler is None or _workspace_controlled(Path(compiler), workspace):
        raise GoDriverUnavailableError("go_missing", "go was not found on PATH outside the workspace")
    return compiler


def _binary_path(cache: Path, source: bytes, module: bytes, toolchain: bytes) -> Path:
    key = hashlib.sha256(source + module + b"\0" + toolchain).hexdigest()
    return cache / (f"go_ast-{key}" + (".exe" if os.name == "nt" else ""))


def _build(compiler: str, cwd: Path, env: dict[str, str], timeout: float,
           source: bytes, module: bytes, binary: Path, workspace: Path) -> None:
    atomic_write_bytes(cwd / "go_ast.go", source)
    atomic_write_bytes(cwd / "go.mod", module)
    output = cwd / binary.name
    _run([compiler, "build", "-trimpath", "-o", str(output), "."], cwd, env, timeout)
    if not _cached(output, workspace):
        raise GoDriverUnavailableError("build_failed", "go build did not produce a complete executable")
    if os.name == "posix":
        output.chmod(0o700)
    with output.open("r+b") as stream:
        os.fsync(stream.fileno())
    _safe_path(binary, workspace)
    os.replace(output, binary)
    fsync_dir(binary.parent)


def inspect_go_driver(workspace_root: Path) -> GoDriverStatus:
    """Probe metadata and cache state without creating directories, locks or binaries.

    ``go help environment`` documents GO111MODULE=off as GOPATH mode: this
    metadata-only probe ignores parent go.mod pins. Actual builds use module mode.
    """
    workspace = Path(workspace_root).resolve()
    try:
        source, module = _packaged_sources(workspace)
        compiler = _compiler(workspace)
        cache = _cache_directory(workspace, create=False)
        for cwd in (cache, *cache.parents):
            if cwd.is_dir():
                break
        else:
            raise GoDriverUnavailableError("cache_unsafe", "no existing directory for the Go metadata probe")
        env = {**_environment(workspace), "GO111MODULE": "off"}
        toolchain = _toolchain(compiler, cwd, env)
        binary = _binary_path(cache, source, module, toolchain)
        hit = _cached(binary, workspace)
        if not hit:
            _safe_path(binary.with_suffix(".lock"), workspace)
        goversion, goos, goarch = toolchain.decode("ascii").splitlines()
        return GoDriverStatus(Path(compiler), goversion, goos, goarch, binary, hit)
    except OSError as exc:
        raise GoDriverUnavailableError("build_failed", str(exc)) from exc


def prepare_go_driver(workspace_root: Path, *, timeout: float = 120.0) -> Path:
    """Return the cached executable, or a reasoned failure; never run repository code.

    The build owns its 120-second default deadline, independent of driver parsing.
    Concurrent callers wait on one cache-key lock and recheck after acquiring it.
    """
    workspace = Path(workspace_root).resolve()
    try:
        source, module = _packaged_sources(workspace)
        compiler = _compiler(workspace)
        cache = _cache_directory(workspace)
        env = _environment(workspace)
        build_dir = Path(tempfile.mkdtemp(prefix=".go-build-", dir=cache))
        cleanup_allowed, original = True, None
        try:
            toolchain = _toolchain(compiler, build_dir, env)
            binary = _binary_path(cache, source, module, toolchain)
            if _cached(binary, workspace):
                return binary
            lock = binary.with_suffix(".lock")
            _safe_path(lock, workspace)
            with file_lock(lock, timeout=max(0.0, timeout) + 3.0):
                _safe_path(cache, workspace, directory=True)
                if not _cached(binary, workspace):
                    _build(compiler, build_dir, env, timeout, source, module, binary, workspace)
            return binary
        except _GoCleanupFailure:
            cleanup_allowed = False
            raise
        except BaseException as exc:
            original = exc
            raise
        finally:
            if cleanup_allowed:
                try:
                    shutil.rmtree(build_dir)
                except OSError as exc:
                    prior = f"{original}; " if original is not None else ""
                    raise GoDriverUnavailableError(
                        "build_failed", f"{prior}private build directory cleanup failed: {exc}") from exc
    except GoDriverUnavailableError:
        raise
    except PathTraversalError as exc:
        raise GoDriverUnavailableError("cache_unsafe", str(exc)) from exc
    except (OSError, LockTimeoutError) as exc:
        raise GoDriverUnavailableError("build_failed", str(exc)) from exc
