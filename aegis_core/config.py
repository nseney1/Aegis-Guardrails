"""Configuration: one repo file, one user file, four environment variables (D10, D11).

``.aegis/config.json`` (committed, so agent- and PR-writable) holds v1 keys::

    {"v": 1,
     "hosts": ["codex-cli", "claude-code"],
     "jit": {"max_tokens": 2000, "scan_window_s": 3600},
     "expiry": {"days": 30, "per_type": {"trap": 60, "invariant": null}},
     "ast": {"packaged_drivers": ["rs", "ts"]}}

It can never name a command: a key that would (``drivers``, ``slots``, ``llm_cmd``…) is
ignored with a warning, and ``ast.packaged_drivers`` only opts in to drivers that ship
inside aegis. ``~/.aegis/config.json`` (per developer, outside every repository) is the
only source of command-like values::

    {"v": 1, "drivers": {"md": "/usr/local/bin/md-ast"}, "slots": {"TOOL_RUN": "Bash"}}

The environment is read here and nowhere else: ``AEGIS_WORKSPACE`` (operator pin),
``AEGIS_CLIENT`` (host identity), ``AEGIS_MAX_JIT_TOKENS`` and ``AEGIS_LLM_CMD``.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass, field
import json
import math
import os
from pathlib import Path
import re
import stat
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from aegis_core.errors import AegisValidationError, PathTraversalError
from aegis_core.primitives import is_within, strict_loads
from aegis_core.workspace.layout import AEGIS_DIRNAME, UserLayout, WorkspaceLayout

__all__ = [
    "CONFIG_VERSION",
    "ConfigError",
    "DEFAULT_SCAN_WINDOW_S",
    "ENV_CLIENT",
    "ENV_LLM_CMD",
    "ENV_MAX_JIT_TOKENS",
    "ENV_VARS",
    "ENV_WORKSPACE",
    "MAX_CONFIG_BYTES",
    "RepoConfig",
    "SCANNER_PRESETS",
    "UserConfig",
    "env_client",
    "env_github_step_summary",
    "env_llm_cmd",
    "env_max_jit_tokens",
    "env_workspace",
    "jit_max_tokens",
    "parse_capture_mode",
    "read_capped",
    "read_user_config",
    "scan_window_s",
    "update_repo_config",
    "user_scanners",
]

CONFIG_VERSION = 1
MAX_CONFIG_BYTES = 64 * 1024
DEFAULT_EXPIRY_DAYS = 30
DEFAULT_HALF_LIFE_SESSIONS = 30
DEFAULT_EPSILON = 0.01
# How long an aegis_scan row lets the scan-before-edit hook pass an edit of its files.
# Bounded: the file is committed, so a huge value must not switch the gate off.
DEFAULT_SCAN_WINDOW_S = 3600
SCAN_WINDOW_RANGE = (60, 86400)
REPO_LABEL = f"{AEGIS_DIRNAME}/config.json"
USER_LABEL = f"~/{AEGIS_DIRNAME}/config.json"

ENV_WORKSPACE = "AEGIS_WORKSPACE"
ENV_CLIENT = "AEGIS_CLIENT"
ENV_MAX_JIT_TOKENS = "AEGIS_MAX_JIT_TOKENS"
ENV_LLM_CMD = "AEGIS_LLM_CMD"
ENV_VARS = (ENV_WORKSPACE, ENV_CLIENT, ENV_MAX_JIT_TOKENS, ENV_LLM_CMD)

_DECAY_KEYS = ("half_life_sessions", "epsilon")
# "fitness" and the top-level decay keys are known (warned about, not counted as unknown keys).
_REPO_KEYS = frozenset({"v", "hosts", "jit", "expiry", "ast", "fitness", *_DECAY_KEYS})
# tests, rules, perf, regression, scanners and insights are read through read_user_config by their consumers.
_USER_KEYS = frozenset({"v", "drivers", "slots", "arbiter_vendor", "tests", "rules", "perf", "regression", "ci",
                        "scanners", "insights"})
#: The scanner presets the user-scope ``scanners`` key may name (aegis_core.verification.scanners).
SCANNER_PRESETS = ("ruff", "gitleaks")
# Keys a repository might use to smuggle in a command. Only these names (aegis's own
# vocabulary) are ever echoed in a warning; any other unknown key is only counted,
# since warnings reach the agent and key names are repo-chosen text.
_COMMAND_KEYS = frozenset({
    "drivers", "driver", "slots", "commands", "command", "cmd", "llm_cmd", "llm_command",
    "ast_driver", "test_runner", "hooks", "exec", "shell",
})
_MAX_LISTED = 5
_LISTABLE_DRIVER_KEY = re.compile(r"ast_driver(?:_[a-z0-9]{1,8})?")
_EXTENSION = re.compile(r"[a-z0-9]{1,8}")
_WORKFLOW_NAME = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9._-]*\.ya?ml")


class ConfigError(AegisValidationError):
    """A configuration file exists but cannot be used. The message names only its label."""


# ── Environment (D11) ────────────────────────────────────────────────────────

def _env(name: str, environ: Optional[Mapping[str, str]]) -> Optional[str]:
    value = (os.environ if environ is None else environ).get(name)
    return value if value and value.strip() else None


def env_workspace(environ: Optional[Mapping[str, str]] = None) -> Optional[str]:
    """``AEGIS_WORKSPACE``: the operator's workspace pin, or None."""
    return _env(ENV_WORKSPACE, environ)


def env_client(environ: Optional[Mapping[str, str]] = None) -> Optional[str]:
    """``AEGIS_CLIENT``: the host id a registration wrote, or None."""
    value = _env(ENV_CLIENT, environ)
    return value.strip() if value else None


def env_llm_cmd(environ: Optional[Mapping[str, str]] = None) -> Optional[str]:
    """``AEGIS_LLM_CMD``: the Layer-2 model command, or None."""
    return _env(ENV_LLM_CMD, environ)


def env_github_step_summary(environ: Optional[Mapping[str, str]] = None) -> Optional[str]:
    """``GITHUB_STEP_SUMMARY``: path to GitHub Actions job summary file, or None."""
    return _env("GITHUB_STEP_SUMMARY", environ)


def env_max_jit_tokens(environ: Optional[Mapping[str, str]] = None) -> Optional[int]:
    """``AEGIS_MAX_JIT_TOKENS`` as a positive int; None when unset or not a positive int."""
    return _positive_int(_env(ENV_MAX_JIT_TOKENS, environ))


def _positive_int(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    try:
        number = int(str(value).strip()) if isinstance(value, str) else value
    except (TypeError, ValueError):
        return None
    return number if isinstance(number, int) and number > 0 else None


def _valid_half_life_sessions(value: Any) -> Optional[int]:
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    return _positive_int(value)


def _valid_epsilon(value: Any) -> Optional[float]:
    if isinstance(value, bool):
        return None
    try:
        number = float(str(value).strip()) if isinstance(value, str) else float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) and 0.0 < number < 1.0 else None


# ── Reading files ────────────────────────────────────────────────────────────

def read_capped(fd: int, limit: int) -> bytes:
    data = b""
    while len(data) <= limit:
        chunk = os.read(fd, limit + 1 - len(data))
        if not chunk:
            break
        data += chunk
    return data


def _read_json(path: Path, label: str) -> Optional[Dict[str, Any]]:
    """The JSON object in ``path``, or None if there is no file.

    Raises ConfigError when the file cannot be read, is not a regular file (a FIFO
    would block, /dev/zero never ends), is larger than MAX_CONFIG_BYTES or is not a
    JSON object. Messages name only ``label``, never the path the file resolves to.
    """
    # O_NONBLOCK: opening a FIFO for reading would otherwise wait for a writer. The type
    # check runs on the opened descriptor, so a swap after the check cannot bypass it.
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags)
    except (FileNotFoundError, NotADirectoryError):
        return None
    except OSError as exc:
        raise ConfigError(f"cannot read {label}") from exc
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ConfigError(f"{label} is not a regular file")
        data = read_capped(fd, MAX_CONFIG_BYTES)
    except OSError as exc:
        raise ConfigError(f"cannot read {label}") from exc
    finally:
        os.close(fd)
    if len(data) > MAX_CONFIG_BYTES:
        raise ConfigError(f"{label} is larger than {MAX_CONFIG_BYTES // 1024} KiB")
    try:
        value = strict_loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise ConfigError(f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise ConfigError(f"{label} must hold a JSON object")
    version = value.get("v", CONFIG_VERSION)
    if version != CONFIG_VERSION:
        raise ConfigError(f"{label} has version {version!r}; this aegis reads version {CONFIG_VERSION}")
    return value


def _names(keys: Sequence[str]) -> str:
    """'N key(s) (names)' for a warning: only aegis's own key names are listed (at most
    five), since keys are repo-chosen text and warnings reach the agent."""
    listed = [k for k in keys if k in _COMMAND_KEYS or _LISTABLE_DRIVER_KEY.fullmatch(k)][:_MAX_LISTED]
    rest = len(keys) - len(listed)
    names = ", ".join(repr(k) for k in listed)
    if rest:
        names = f"{names} and {rest} more" if names else "names not shown"
    return f"{len(keys)} key(s) ({names})"


# ── Repository config ────────────────────────────────────────────────────────

@dataclass(frozen=True)
class RepoConfig:
    """The usable part of ``.aegis/config.json`` plus why anything was ignored."""

    hosts: Tuple[str, ...] = ()
    jit_max_tokens: Optional[int] = None
    scan_window_s: int = DEFAULT_SCAN_WINDOW_S
    expiry_days: Optional[int] = DEFAULT_EXPIRY_DAYS
    expiry_per_type: Mapping[str, Optional[int]] = field(default_factory=dict)
    half_life_sessions: int = DEFAULT_HALF_LIFE_SESSIONS
    epsilon: float = DEFAULT_EPSILON
    packaged_drivers: Tuple[str, ...] = ()
    warnings: Tuple[str, ...] = ()

    def expiry_for(self, rule_type: Optional[str]) -> Optional[int]:
        """Days a rule of ``rule_type`` lasted without a trigger (None: never). Parsed for N-1 configs
        and inert since 4.4: fitness decays by exposed sessions, never by calendar days (R-evidence-15)."""
        if rule_type and rule_type in self.expiry_per_type:
            return self.expiry_per_type[rule_type]
        return self.expiry_days

    @classmethod
    def load(cls, workspace_root: Any) -> "RepoConfig":
        """Read ``.aegis/config.json``; a missing file gives the defaults.

        Raises ConfigError if the file exists but cannot be used. A file that resolves
        outside the workspace (a committed symlink) is ignored with a warning.
        """
        layout = WorkspaceLayout(Path(os.fspath(workspace_root)).resolve())
        path = layout.config_file
        if os.path.lexists(path) and not is_within(path, layout.root, unresolvable=False):
            return cls(warnings=(f"ignored {REPO_LABEL}: it resolves to a path outside the workspace",))
        raw = _read_json(path, REPO_LABEL)
        return cls() if raw is None else cls.parse(raw)

    @classmethod
    def parse(cls, raw: Mapping[str, Any]) -> "RepoConfig":
        warnings: List[str] = []
        unknown = [k for k in raw if k not in _REPO_KEYS]
        commands = [k for k in unknown if k.lower() in _COMMAND_KEYS or k.lower().startswith("ast_driver")]
        others = [k for k in unknown if k not in commands]
        if commands:
            warnings.append(
                f"ignored {_names(commands)} in {REPO_LABEL}: repository config cannot name commands "
                f"or set slots; set them in {USER_LABEL}"
            )
        if others:
            warnings.append(f"ignored {len(others)} unknown key(s) in {REPO_LABEL}")

        hosts = raw.get("hosts", [])
        if not isinstance(hosts, list) or not all(isinstance(h, str) and h.strip() for h in hosts):
            warnings.append(f"ignored 'hosts' in {REPO_LABEL}: it must be a list of host ids")
            hosts = []

        jit = raw.get("jit", {})
        max_tokens = None
        window = DEFAULT_SCAN_WINDOW_S
        if isinstance(jit, dict):
            if "max_tokens" in jit:
                max_tokens = _positive_int(jit["max_tokens"])
                if max_tokens is None:
                    warnings.append(f"ignored 'jit.max_tokens' in {REPO_LABEL}: it must be a positive integer")
            if "scan_window_s" in jit:
                low, high = SCAN_WINDOW_RANGE
                configured = _positive_int(jit["scan_window_s"])
                if configured is not None and low <= configured <= high:
                    window = configured
                else:
                    warnings.append(
                        f"ignored 'jit.scan_window_s' in {REPO_LABEL}: it must be an integer from {low} to {high}"
                    )
            extra = set(jit) - {"max_tokens", "scan_window_s"}
            if extra:
                warnings.append(f"ignored {len(extra)} unknown key(s) under 'jit' in {REPO_LABEL}")
        else:
            warnings.append(f"ignored 'jit' in {REPO_LABEL}: it must be an object")

        expiry_days: Optional[int] = DEFAULT_EXPIRY_DAYS
        per_type: Dict[str, Optional[int]] = {}
        expiry = raw.get("expiry", {})
        if isinstance(expiry, dict):
            if "days" in expiry:
                days = expiry["days"]
                if days is None or _positive_int(days) is not None:
                    expiry_days = None if days is None else _positive_int(days)
                else:
                    warnings.append(f"ignored 'expiry.days' in {REPO_LABEL}: it must be a positive integer or null")
            types = expiry.get("per_type", {})
            if isinstance(types, dict):
                from aegis_core.taxonomy import CANONICAL_RULE_TYPES

                for rule_type, days in types.items():
                    if rule_type in CANONICAL_RULE_TYPES and (days is None or _positive_int(days) is not None):
                        per_type[rule_type] = None if days is None else _positive_int(days)
                    else:
                        warnings.append(
                            f"ignored an 'expiry.per_type' entry in {REPO_LABEL}: keys are rule types "
                            "and values positive integers or null"
                        )
                        break
            else:
                warnings.append(f"ignored 'expiry.per_type' in {REPO_LABEL}: it must be an object")
        else:
            warnings.append(f"ignored 'expiry' in {REPO_LABEL}: it must be an object")

        # The decay keys are read under ``expiry`` only; the top-level and ``fitness`` spellings
        # earlier releases accepted are named in one warning (their values never echoed).
        fitness_raw = raw.get("fitness", {})
        if not isinstance(fitness_raw, Mapping):
            warnings.append(f"ignored 'fitness' in {REPO_LABEL}: it must be an object")
            fitness_raw = {}
        if any(key in where for where in (raw, fitness_raw) for key in _DECAY_KEYS):
            warnings.append(f"ignored decay key(s) in {REPO_LABEL} outside 'expiry': use expiry.half_life_sessions "
                            "and expiry.epsilon")
        expiry_map = expiry if isinstance(expiry, Mapping) else {}
        half_life_sessions, epsilon = DEFAULT_HALF_LIFE_SESSIONS, DEFAULT_EPSILON
        if "half_life_sessions" in expiry_map:
            parsed_hl = _valid_half_life_sessions(expiry_map["half_life_sessions"])
            if parsed_hl is None:
                warnings.append(f"ignored 'expiry.half_life_sessions' in {REPO_LABEL}: it must be a positive integer")
            half_life_sessions = parsed_hl or half_life_sessions
        if "epsilon" in expiry_map:
            parsed_eps = _valid_epsilon(expiry_map["epsilon"])
            if parsed_eps is None:
                warnings.append(f"ignored 'expiry.epsilon' in {REPO_LABEL}: it must be a number between 0 and 1")
            epsilon = parsed_eps or epsilon

        packaged: List[str] = []
        ast = raw.get("ast", {})
        if isinstance(ast, dict):
            # Only the shape is checked here (L0); aegis_core.skills.slots drops an extension
            # with no driver shipped inside aegis, with a warning.
            wanted = ast.get("packaged_drivers", [])
            if isinstance(wanted, list):
                for ext in wanted:
                    clean = ext.strip().lower().lstrip(".") if isinstance(ext, str) else ""
                    if _EXTENSION.fullmatch(clean):
                        if clean not in packaged:
                            packaged.append(clean)
                    else:
                        warnings.append(
                            f"ignored an 'ast.packaged_drivers' entry in {REPO_LABEL}: entries are "
                            "file extensions such as \"rs\""
                        )
                        break
            else:
                warnings.append(f"ignored 'ast.packaged_drivers' in {REPO_LABEL}: it must be a list of extensions")
            extra = [k for k in ast if k != "packaged_drivers"]
            if extra:
                warnings.append(
                    f"ignored {len(extra)} key(s) under 'ast' in {REPO_LABEL}: repository config cannot "
                    f"name driver commands; set them in {USER_LABEL}"
                )
        else:
            warnings.append(f"ignored 'ast' in {REPO_LABEL}: it must be an object")

        return cls(
            hosts=tuple(h.strip() for h in hosts),
            jit_max_tokens=max_tokens,
            scan_window_s=window,
            expiry_days=expiry_days,
            expiry_per_type=per_type,
            half_life_sessions=half_life_sessions,
            epsilon=epsilon,
            packaged_drivers=tuple(packaged),
            warnings=tuple(warnings),
        )


def update_repo_config(workspace_root: Any, change: Callable[[Dict[str, Any]], None]) -> Dict[str, Any]:
    """Apply ``change`` to ``.aegis/config.json`` under the workspace lock; return the new content.

    Refuses (PathTraversalError) when ``.aegis`` or the file is a symlink: writing
    through one could plant a trusted user-scope file. An unreadable existing file is
    left alone (ConfigError). Unknown keys are kept as they are.
    """
    from aegis_core.storage import atomic_write_text, locked

    layout = WorkspaceLayout(Path(os.fspath(workspace_root)).resolve())
    for path in (layout.aegis_dir, layout.config_file):
        if path.is_symlink():
            raise PathTraversalError(
                f"refusing to write {REPO_LABEL}: {path} is a symlink; aegis writes .aegis/ only as "
                "regular files inside the workspace"
            )
    with locked(layout.root):
        current = _read_json(layout.config_file, REPO_LABEL) or {}
        data = copy.deepcopy(current)  # ``change`` may edit nested objects in place
        data["v"] = CONFIG_VERSION
        change(data)
        ordered = {"v": data.pop("v"), **data}
        if ordered != current or not layout.config_file.is_file():
            atomic_write_text(layout.config_file, json.dumps(ordered, indent=2, ensure_ascii=False) + "\n")
        return ordered


# ── User config ──────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class UserConfig:
    """``~/.aegis/config.json``: driver commands by extension and slot overrides."""

    drivers: Mapping[str, str] = field(default_factory=dict)
    slots: Mapping[str, str] = field(default_factory=dict)
    warnings: Tuple[str, ...] = ()
    arbiter_vendor: Optional[str] = None
    ci_workflow: Optional[str] = None
    insights_capture: Optional[str] = None

    @classmethod
    def load(cls, workspace_root: Any = None, user: Optional[UserLayout] = None) -> "UserConfig":
        """Read the user config; nothing when no home directory resolves.

        A user file that lies inside ``workspace_root`` is repository content, not user
        scope, and is ignored with a warning. Raises ConfigError if the file exists but
        cannot be used.
        """
        user = user or UserLayout.current()
        if user is None:
            return cls()
        path = user.config_file
        inside = workspace_root is not None and is_within(path, os.fspath(workspace_root), unresolvable=True)
        if inside and os.path.lexists(path):
            return cls(warnings=(
                f"ignored {USER_LABEL} as user scope: it lies inside the workspace, "
                "so it is treated as repository content",
            ))
        raw = _read_json(path, USER_LABEL)
        return cls() if raw is None else cls.parse(raw)

    @classmethod
    def parse(cls, raw: Mapping[str, Any]) -> "UserConfig":
        warnings: List[str] = []
        unknown = [k for k in raw if k not in _USER_KEYS]
        if unknown:
            warnings.append(f"ignored {len(unknown)} unknown key(s) in {USER_LABEL}")
        drivers: Dict[str, str] = {}
        raw_drivers = raw.get("drivers", {})
        if isinstance(raw_drivers, dict):
            for ext, command in raw_drivers.items():
                clean = str(ext).strip().lower().lstrip(".")
                if clean and isinstance(command, str) and command.strip():
                    drivers[clean] = command.strip()
        else:
            warnings.append(f"ignored 'drivers' in {USER_LABEL}: it must map extensions to commands")
        slots: Dict[str, str] = {}
        raw_slots = raw.get("slots", {})
        if isinstance(raw_slots, dict):
            slots = {str(k): str(v) for k, v in raw_slots.items() if v is not None}
        else:
            warnings.append(f"ignored 'slots' in {USER_LABEL}: it must be an object")
        raw_vendor = raw.get("arbiter_vendor")
        arbiter_vendor = str(raw_vendor).strip() if isinstance(raw_vendor, str) and raw_vendor.strip() else None
        ci_workflow = None
        if "ci" in raw:
            raw_ci = raw["ci"]
            ci_workflow = ci_workflow_name(raw_ci.get("workflow")) if isinstance(raw_ci, dict) else None
            if ci_workflow is None:
                warnings.append(f"ignored 'ci.workflow' in {USER_LABEL}: it must be a bare .yml or .yaml file name")
        if "scanners" in raw and (not isinstance(raw["scanners"], list)
                                  or any(name not in SCANNER_PRESETS for name in raw["scanners"])):
            warnings.append(f"ignored entries of 'scanners' in {USER_LABEL}: it lists preset names "
                            f"({', '.join(SCANNER_PRESETS)})")
        section, capture = raw.get("insights"), None
        if section is not None and not isinstance(section, dict):
            warnings.append(f"ignored 'insights' in {USER_LABEL}: it must be an object")
        elif section and section.get("capture") is not None:
            capture = parse_capture_mode(section["capture"])
            if capture is None:
                warnings.append(f"ignored 'insights.capture' in {USER_LABEL}: expected off, counters or excerpts")
        return cls(drivers=drivers, slots=slots, warnings=tuple(warnings), arbiter_vendor=arbiter_vendor,
                   ci_workflow=ci_workflow, insights_capture=capture)


def parse_capture_mode(value: Any) -> Optional[str]:
    """``insights.capture`` as 'off', 'counters' or 'excerpts' (stripped, any case), else None."""
    mode = value.strip().lower() if isinstance(value, str) else None
    return mode if mode in ("off", "counters", "excerpts") else None


def ci_workflow_name(value: Any) -> Optional[str]:
    """``value`` when it is a bare workflow file name (``aegis.yml``): 1 to 100 characters of
    ``[A-Za-z0-9._-]`` ending ``.yml`` or ``.yaml``, no leading dot, no ``..``; else None."""
    if isinstance(value, str) and len(value) <= 100 and _WORKFLOW_NAME.fullmatch(value) and ".." not in value:
        return value
    return None


def user_ci_workflow(workspace_root: Any = None) -> Optional[str]:
    """``ci.workflow`` of the user-scope config when usable: the workflow whose runs confirm credit.
    The repository config never names it (an agent could point credit at a workflow it controls)."""
    raw = read_user_config(workspace_root) or {}
    ci = raw.get("ci")
    return ci_workflow_name(ci.get("workflow")) if isinstance(ci, dict) else None


def user_scanners(workspace_root: Any = None) -> List[str]:
    """The presets ``scanners`` in the user-scope config names, known names only, in order. The
    repository never names them: a scanner is a program aegis runs over its code."""
    names = (read_user_config(workspace_root) or {}).get("scanners")
    if not isinstance(names, list):
        return []
    return list(dict.fromkeys(name for name in names if isinstance(name, str) and name in SCANNER_PRESETS))


def read_user_config(
    workspace_root: Any = None, *, user: Optional[UserLayout] = None, path: Any = None,
) -> Optional[Dict[str, Any]]:
    """The user-scope config as a dict, or None; never raises.

    The one lenient reader for the command-like user keys (``tests.command``,
    ``rules.base_ref``, ``perf.command``, ``regression.*``, ``scanners``): the repository never supplies
    them. ``path`` overrides ``~/.aegis/config.json``. None without a home directory, when
    the file lies inside ``workspace_root`` (repository content), and whenever
    UserConfig.load would raise ConfigError (not a regular file, over the size cap, not a
    JSON object, or a version this aegis does not read).
    """
    if path is None:
        user = user or UserLayout.current()
        if user is None:
            return None
        path = user.config_file
    path = Path(os.fspath(path))
    if workspace_root is not None and is_within(path, os.fspath(workspace_root), unresolvable=True):
        return None
    try:
        return _read_json(path, USER_LABEL)
    except ConfigError:
        return None


# ── Resolved values ──────────────────────────────────────────────────────────

def jit_max_tokens(workspace_root: Any, default: int) -> int:
    """The scan token budget: AEGIS_MAX_JIT_TOKENS, then repo ``jit.max_tokens``, then ``default``.

    An unusable repo config falls back to the default: the budget must never cost the
    agent its guidance.
    """
    from_env = env_max_jit_tokens()
    if from_env is not None:
        return from_env
    if workspace_root:
        try:
            configured = RepoConfig.load(workspace_root).jit_max_tokens
        except ConfigError:
            configured = None
        if configured is not None:
            return configured
    return default


def scan_window_s(workspace_root: Any) -> int:
    """The repo's ``jit.scan_window_s``, or DEFAULT_SCAN_WINDOW_S when the config is
    missing, unusable or has no valid value (never raises for the file)."""
    try:
        return RepoConfig.load(workspace_root).scan_window_s
    except (ConfigError, OSError):
        return DEFAULT_SCAN_WINDOW_S
