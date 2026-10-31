"""User-scoped command plans and no-fetch environments shared by language checks.

Commands run user/repository code and are not a network sandbox. These controls
prevent Aegis's defaults and toolchain selection from initiating dependency fetches.
"""
from __future__ import annotations

from dataclasses import dataclass
import math
import os
from pathlib import Path
import re
import shlex
from typing import Mapping, Sequence

from aegis_core.config import read_user_config
from aegis_core.pathlookup import is_bare, which
from aegis_core.primitives import is_within, key_within

__all__ = ["LanguageSettings", "expand_command", "language_environment", "language_settings", "resolve_executable",
           "rebase_snapshot_arguments"]

_DEADLINES = {"ts": 300.0, "go": 300.0, "rust": 900.0}
_PLACEHOLDER = re.compile(r"\{([A-Za-z_][A-Za-z_0-9]*)\}")
_NAMES = frozenset({"packages", "files", "filters", "junit", "out"})


@dataclass(frozen=True)
class LanguageSettings:
    """An optional user command; a missing command leaves defaults to the adapter."""

    command: tuple[str, ...] | None
    timeout_s: float


def language_settings(workspace: Path, language: str, *, coverage: bool = False) -> LanguageSettings:
    """Read the user's language table, never the repository's configuration."""
    if language not in _DEADLINES:
        raise ValueError(f"unsupported language: {language}")
    section = "coverage" if coverage else "tests"
    raw = (read_user_config(workspace) or {}).get(section, {})
    languages = raw.get("languages", {}) if isinstance(raw, dict) else None
    if not isinstance(languages, dict):
        raise ValueError(f"invalid {section}.languages")
    settings = languages.get(language, {})
    prefix = f"{section}.languages.{language}"
    if not isinstance(settings, dict):
        raise ValueError(f"invalid {prefix}")
    command = None
    if "command" in settings:
        words = settings["command"]
        if isinstance(words, str):
            try:
                words = shlex.split(words, posix=os.name != "nt")
            except ValueError as exc:
                raise ValueError(f"invalid {prefix}.command") from exc
        if not isinstance(words, list) or not words or not all(
                isinstance(word, str) and word and "\0" not in word for word in words):
            raise ValueError(f"invalid {prefix}.command")
        command = tuple(words)
    timeout = settings.get("timeout_s", _DEADLINES[language]) if not coverage else _DEADLINES[language]
    try:
        valid = not isinstance(timeout, bool) and isinstance(timeout, (int, float)) and math.isfinite(timeout) and timeout > 0
    except OverflowError:
        valid = False
    if not valid:
        raise ValueError(f"invalid {prefix}.timeout_s")
    return LanguageSettings(command, float(timeout))


def expand_command(command: Sequence[str], values: Mapping[str, str | Sequence[str]]) -> list[str]:
    """Expand named argv placeholders without a shell or whitespace splitting."""
    def selected(name: str) -> tuple[str, ...]:
        if name not in _NAMES:
            raise ValueError(f"unknown placeholder: {name}")
        if name not in values:
            raise ValueError(f"missing placeholder: {name}")
        raw = values[name]
        parts = (raw,) if isinstance(raw, str) else tuple(raw)
        if not all(isinstance(value, str) and value and "\0" not in value for value in parts):
            raise ValueError(f"invalid placeholder value: {name}")
        return parts

    argv = []
    for word in command:
        exact = _PLACEHOLDER.fullmatch(word)
        if exact:
            argv.extend(selected(exact[1]))
            continue

        def replace(match):
            parts = selected(match[1])
            if len(parts) != 1:
                raise ValueError(f"embedded placeholder requires one value: {match[1]}")
            return parts[0]

        argv.append(_PLACEHOLDER.sub(replace, word))
    return argv


def resolve_executable(command: str, workspace: Path) -> str | None:
    """Resolve a parent-selected executable outside the repository and relative PATH entries."""
    if is_bare(command):
        return which(command, outside=workspace)
    if not os.path.isabs(command) or is_within(command, workspace, unresolvable=True) or key_within(
            os.path.normcase(os.path.abspath(command)), os.path.normcase(os.path.abspath(workspace))):
        return None
    path = Path(command)
    return str(path) if path.is_file() and (os.name == "nt" or os.access(path, os.X_OK)) else None


def rebase_snapshot_arguments(argv: Sequence[str], workspace: Path, snapshot: Path) -> list[str]:
    """Rebase lexical repository paths, including a chosen executable, without changing logical argv."""
    root, destination = Path(os.path.abspath(workspace)), Path(snapshot)
    result = []
    for word in argv:
        prefix, separator, raw = ("", "", word) if os.path.isabs(word) else word.partition("=")
        raw = raw if separator else word
        if os.path.isabs(raw):
            try:
                mapped = str(destination / Path(os.path.abspath(raw)).relative_to(root))
                word = prefix + "=" + mapped if separator else mapped
            except ValueError:
                pass  # An explicitly chosen external path stays external.
        result.append(word)
    return result


def language_environment(language: str, base: Mapping[str, str], *, parent: Mapping[str, str] | None = None,
                         executable: str | None = None, rust_toolchain: str | None = None,
                         cargo_target: str | None = None) -> dict[str, str]:
    """Extend a hermetic base with offline language policy and explicitly retained caches.

    The caller resolves an installed Rust toolchain in an empty directory before
    supplying its name here; repository pins never select it.
    """
    if language not in _DEADLINES:
        raise ValueError(f"unsupported language: {language}")
    parent = os.environ if parent is None else parent
    env = dict(base)
    if language == "go":
        env.update(GOTOOLCHAIN="local", GOFLAGS="-mod=readonly", GOPROXY="off", GOWORK="off", GOENV="off")
        retained = ("GOMODCACHE", "GOCACHE")
    elif language == "rust":
        if not rust_toolchain or not re.fullmatch(r"[A-Za-z0-9_.+-]+", rust_toolchain) or not cargo_target \
                or not os.path.isabs(cargo_target):
            raise ValueError("Rust requires a resolved installed toolchain and absolute cache target")
        env.update(RUSTUP_TOOLCHAIN=rust_toolchain, RUSTUP_AUTO_INSTALL="0", CARGO_NET_OFFLINE="true",
                   CARGO_TARGET_DIR=cargo_target)
        retained = ("CARGO_HOME", "RUSTUP_HOME")
    else:
        retained = ()
    env.update((name, parent[name]) for name in retained if parent.get(name))
    if executable:
        env["PATH"] = os.path.dirname(executable) + os.pathsep + env.get("PATH", os.defpath)
    return env
