"""Public runtime preparation shared by language tests and coverage.

Pure argv/environment policy lives in testplans; testexec owns every process.
Metadata probes run once in an empty directory outside the repository.
"""
from __future__ import annotations

import hashlib
import os
import re
import stat
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from aegis_core import testexec
from aegis_core.primitives import is_within, key_within
from aegis_core.testplans import language_environment, resolve_executable

__all__ = [
    "LanguageRuntime",
    "RuntimeUnavailable",
    "language_runtime_environment",
    "prepare_language_runtime",
    "read_runtime_report",
]
_MAX_REPORT = 8 * 1024 * 1024


class RuntimeUnavailable(Exception):
    def __init__(self, reason: str, detail: str):
        super().__init__(detail)
        self.reason, self.detail = reason, detail


@dataclass(frozen=True)
class LanguageRuntime:
    language: str
    command: tuple[str, ...]
    parent_caches: tuple[tuple[str, str], ...] = ()
    rust_toolchain: str | None = None
    cargo_target: str | None = None


def _outside(path: Path, workspace: Path) -> bool:
    return not (is_within(path, workspace, unresolvable=True) or key_within(
        os.path.normcase(os.path.abspath(path)), os.path.normcase(os.path.abspath(workspace))))


def _base(scratch: Path) -> dict[str, str]:
    home, tmp = scratch / "home", scratch / "tmp"
    home.mkdir(parents=True, exist_ok=True)
    tmp.mkdir(parents=True, exist_ok=True)
    return testexec.hermetic_env(home, tmp)


def read_runtime_report(path: Path) -> str:
    """Read the entire bounded regular UTF-8 report, refusing links and special files."""
    try:
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > _MAX_REPORT
                or getattr(info, "st_file_attributes", 0) & 0x400):
            raise RuntimeUnavailable("output_too_large" if info.st_size > _MAX_REPORT else "report_unsafe", path.name)
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
        with os.fdopen(os.open(path, flags), "rb") as stream:
            opened = os.fstat(stream.fileno())
            if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                    or getattr(opened, "st_file_attributes", 0) & 0x400
                    or (info.st_dev, info.st_ino) != (opened.st_dev, opened.st_ino)):
                raise RuntimeUnavailable("report_unsafe", path.name)
            if opened.st_size > _MAX_REPORT:
                raise RuntimeUnavailable("output_too_large", path.name)
            raw = stream.read(_MAX_REPORT + 1)
        if len(raw) > _MAX_REPORT:
            raise RuntimeUnavailable("output_too_large", path.name)
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RuntimeUnavailable("invalid_unicode", path.name) from exc
    except FileNotFoundError as exc:
        raise RuntimeUnavailable("report_missing", path.name) from exc
    except OSError as exc:
        raise RuntimeUnavailable("report_unreadable", f"{path.name}: {exc}") from exc


def _probe(argv: Sequence[str], scratch: Path, env: Mapping[str, str]) -> str:
    cwd = scratch / "neutral"
    cwd.mkdir(parents=True, exist_ok=True)
    if any(cwd.iterdir()):
        raise RuntimeUnavailable("deps_unavailable", "metadata probe cwd is not empty")
    result = testexec.run_tests(argv, cwd, env, 5.0, scratch / "unused.xml", scratch / "probe.log")
    if result.timed_out or result.exit:
        raise RuntimeUnavailable("deps_unavailable", "metadata probe timed out" if result.timed_out else "metadata probe failed")
    try:
        return read_runtime_report(scratch / "probe.log")
    except RuntimeUnavailable as exc:
        raise RuntimeUnavailable("deps_unavailable", f"metadata probe {exc.reason}") from exc


def _cache_root(parent: Mapping[str, str]) -> Path:
    home = Path(parent.get("USERPROFILE" if os.name == "nt" else "HOME", str(Path.home())))
    if os.name == "nt":
        return Path(parent.get("LOCALAPPDATA", str(home / "AppData/Local"))) / "aegis/Cache"
    if sys.platform == "darwin":
        return home / "Library/Caches/aegis"
    return Path(parent.get("XDG_CACHE_HOME", str(home / ".cache"))) / "aegis"



def prepare_language_runtime(workspace: Path, language: str, command: Sequence[str], *, scratch: Path,
                             parent: Mapping[str, str] | None = None) -> LanguageRuntime:
    """Prepare runtime/cache identity independently of selected test IDs or user command tables."""
    if language not in ("go", "ts", "rust"):
        raise ValueError(f"unsupported language: {language}")
    workspace, scratch = Path(workspace).resolve(), Path(scratch).resolve()
    parent = dict(os.environ if parent is None else parent)
    if not _outside(scratch, workspace):
        raise RuntimeUnavailable("deps_unavailable", "scratch must be outside the workspace")
    if not command or not all(isinstance(word, str) and word and "\0" not in word for word in command):
        raise RuntimeUnavailable("deps_unavailable", "invalid runtime command")
    executable = resolve_executable(command[0], workspace)
    if executable is None:
        raise RuntimeUnavailable("deps_unavailable", "runtime executable unavailable outside workspace")
    scratch.mkdir(parents=True, exist_ok=True)
    if any(scratch.iterdir()):
        raise RuntimeUnavailable("deps_unavailable", "scratch must be empty; preserve prior execution evidence")
    env = _base(scratch)
    caches = {name: parent[name] for name in ("GOCACHE", "GOMODCACHE", "CARGO_HOME", "RUSTUP_HOME") if parent.get(name)}
    pin = target = None
    if language == "go" and not {"GOCACHE", "GOMODCACHE"} <= caches.keys():
        go = resolve_executable("go", workspace)
        if go is None:
            raise RuntimeUnavailable("deps_unavailable", "Go cache discovery requires installed Go")
        probe_env = language_environment("go", env, parent=parent, executable=go)
        probe_env.update((key, parent[key]) for key in ("HOME", "USERPROFILE", "GOPATH", "LOCALAPPDATA", "XDG_CACHE_HOME") if parent.get(key))
        values = _probe((go, "env", "GOCACHE", "GOMODCACHE"), scratch, probe_env).strip().splitlines()
        if len(values) != 2 or not all(os.path.isabs(value) for value in values):
            raise RuntimeUnavailable("deps_unavailable", "Go cache probe returned invalid paths")
        for key, value in zip(("GOCACHE", "GOMODCACHE"), values):
            caches.setdefault(key, value)
    elif language == "rust":
        pin, target = _rust(workspace, scratch, parent, env, caches)
    return LanguageRuntime(language, (executable, *command[1:]), tuple(sorted(caches.items())), pin, target)


def _rust(workspace, scratch, parent, env, caches):
    home = Path(parent.get("USERPROFILE" if os.name == "nt" else "HOME", str(Path.home())))
    for name, suffix in (("CARGO_HOME", ".cargo"), ("RUSTUP_HOME", ".rustup")):
        caches.setdefault(name, str(home / suffix))
    rustup = resolve_executable("rustup", workspace)
    if rustup is None or any(not _outside(Path(caches[key]), workspace) for key in ("CARGO_HOME", "RUSTUP_HOME")):
        raise RuntimeUnavailable("deps_unavailable", "installed Rust toolchain unavailable outside workspace")
    probe_env = {**env, **{key: caches[key] for key in ("CARGO_HOME", "RUSTUP_HOME")}, "RUSTUP_AUTO_INSTALL": "0"}
    output = _probe((rustup, "toolchain", "list"), scratch, probe_env)
    defaults = [match[1] for line in output.splitlines() if (match := re.fullmatch(
        r"([A-Za-z0-9_.+-]+) \(([^()]*)\)", line.strip())) and "default" in match[2].replace(",", " ").split()]
    if len(defaults) != 1:
        raise RuntimeUnavailable("deps_unavailable", "unique installed default Rust toolchain unavailable")
    target = _cache_root(parent) / "cargo-target" / hashlib.sha256(str(workspace).encode()).hexdigest()[:24]
    if not target.is_absolute() or not _outside(target, workspace):
        raise RuntimeUnavailable("deps_unavailable", "Cargo target cache must be outside workspace")
    return defaults[0], str(target)


def language_runtime_environment(runtime: LanguageRuntime, scratch: Path) -> dict[str, str]:
    """Make an execution's redirected HOME/temp and fixed offline policy from a prepared runtime."""
    return language_environment(runtime.language, _base(Path(scratch)), parent=dict(runtime.parent_caches),
        executable=runtime.command[0], rust_toolchain=runtime.rust_toolchain, cargo_target=runtime.cargo_target)
