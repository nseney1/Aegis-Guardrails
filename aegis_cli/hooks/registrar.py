"""`aegis hook install --host <h>` / `aegis hook uninstall --host <h>`: register the
per-host PreToolUse hook (v4.1 spec §2 Registration, AD-8 honest tiers).

Each host gets one PreToolUse group that runs ``aegis hook run pre-tool --host <h>``:

- **Claude Code** (exec form, no shell; Claude Code >= 2.1.139, DOC):
  ``~/.claude/settings.json`` (``$CLAUDE_CONFIG_DIR/settings.json``) or, with
  ``--scope project``, ``<repo>/.claude/settings.json``. No ``permissions.deny`` entries:
  the hook parses commands, which deny rules cannot.
- **Codex CLI** (run through ``$SHELL -lc``, DOC): ``~/.codex/hooks.json``
  (``$CODEX_HOME/hooks.json``) or ``<repo>/.codex/hooks.json``, plus
  ``~/.codex/rules/aegis.rules`` (``prefix_rule(... decision="forbidden")``, generated from
  :data:`aegis_core.command_safety.BLOCK_SET`; ``default.rules`` is never touched). The
  entry is byte-stable across re-installs with the same ``aegis``: Codex's trust hash
  covers the handler, and a changed hook is skipped silently until re-trusted in /hooks.
- **Antigravity** (shell, LIVE): group ``aegis`` in ``~/.gemini/config/hooks.json`` or
  ``<repo>/.agents/hooks.json``. The wrapper maps the handler's 75 to agy's blocking 1 and
  every other code (a crash, 126, 127, a missing binary) to 0, and keeps stdout empty.
  agy hooks are ``unavailable`` on Windows (its hook shell is UNVERIFIED there).

Every write follows the host-plane contract of :mod:`aegis_cli.install_hosts`: no
symlinked or multiply-linked file is written, unparseable JSON is refused, the old bytes
go to ``~/.aegis/backups/<UTC stamp>/<scope>/`` first (both scopes' files share a name, and
the Codex rules file is a user file), the replacement is atomic and is re-read
afterwards (a broken Claude settings file silently drops all its hooks, DOC). Aegis
entries are identified by their command (an absolute ``aegis`` followed by ``hook run``),
never by position, and a host never gets an Aegis entry at both scopes. Uninstall reads and
checks every file it would change before it writes the first, and removes the Codex rules
file only with the last Aegis Codex hook.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass, field
from datetime import datetime, timezone  # noqa: F401 - names the 4.3.3 public-names pin holds
import json
import os
from pathlib import Path, PureWindowsPath
import re
import shlex
import sys
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple, Union

from aegis_cli import aegis_import_root
from aegis_core import primitives
from aegis_cli import install_hosts as plane
from aegis_cli.install_hosts import InstallError
from aegis_core import hosts as host_table
from aegis_core.storage import atomic_write_bytes

__all__ = [
    "AEGIS_PATH_CHARSET",
    "CODEX_RULES_HEADER",
    "EVIDENCE",
    "HOOK_HOSTS",
    "HOOK_TIMEOUT_S",
    "INSIGHT_RUNNER",
    "KNOWN_GAPS",
    "SCOPES",
    "TIERS",
    "TRUST_UNCHECKED",
    "UNAVAILABLE",
    "HookResult",
    "ShapeError",
    "UsageError",
    "aegis_command",
    "probe_hook_run",
    "aegis_handlers",
    "codex_rules_file",
    "codex_rules_text",
    "command_tokens",
    "edit_hook_file",
    "handler_aegis",
    "hook_file",
    "hook_group",
    "install",
    "install_insight_hook",
    "is_aegis_handler",
    "matches_install",
    "run_host_install",
    "run_host_uninstall",
    "uninstall",
    "unavailable_reason",
]

HOOK_HOSTS = ("claude-code", "codex-cli", "antigravity")
SCOPES = ("user", "project")
HOOK_TIMEOUT_S = 10
EVENT = "PreToolUse"
AGY_GROUP = "aegis"
MATCHERS = {
    "claude-code": "Bash|PowerShell|Monitor|Write|Edit|NotebookEdit",
    "codex-cli": "Bash|apply_patch",
    "antigravity": "run_command|write_to_file|replace_file_content|multi_replace_file_content",
}
#: What a shell form may contain of the aegis path: no quoting games (spec §2).
AEGIS_PATH_CHARSET = re.compile(r"[A-Za-z0-9._/+-]+")
_CHARSET_TEXT = "[A-Za-z0-9._/+-]+"
UNAVAILABLE = "unavailable"
#: The tier each registration provides, as doctor prints it. Presence is not enforcement.
TIERS = {
    "claude-code": "blocking (documented; fails open on error)",
    "codex-cli": "blocking once trusted in /hooks (documented; fails open)",
    "antigravity": "blocks destructive commands (live); scan gate records only",
}
#: Where each tier claim comes from (LIVE probed, DOC documented, UNVERIFIED neither).
EVIDENCE = {"claude-code": "DOC", "codex-cli": "DOC", "antigravity": "LIVE"}
KNOWN_GAPS = (
    "Edits made through shell commands never reach the edit gate on any host.",
    "Codex write_stdin into an interactive shell has no PreToolUse payload, and the Codex Bash payload "
    "carries no working directory.",
    "Antigravity manage_task with send_input types into a background terminal past run_command.",
    "Aegis never emits an 'ask' decision (it fails open on Codex and soft-denies in agy headless runs).",
    "The hooks fail open on any Aegis error: they are guardrails, not a security boundary.",
)
#: What doctor says of a Codex entry: trust lives in Codex's own state, not in a file Aegis reads.
TRUST_UNCHECKED = "needs approval in /hooks (cannot be checked)"
CODEX_TRUST_STEP = (
    "Codex runs a new or changed hook only after you trust it: open Codex and approve the aegis hook in "
    "/hooks (doctor cannot check this). Until then Codex skips it silently. codex exec has no documented "
    "trust path besides --dangerously-bypass-hook-trust on each run.")
CODEX_RULES_HEADER = ("# aegis:codex-rules v=1 - generated by `aegis hook install --host codex-cli` from the "
                      "Aegis destructive-command block set.\n")
_AEGIS_NAMES = ("aegis", "aegis.exe")
#: ``<python> -I -c INSIGHT_RUNNER <import root> --host ...``: -I keeps the cwd and PYTHON*
#: off sys.path, so a repository cannot substitute its own aegis_cli (management._HOOK_RUNNER).
INSIGHT_RUNNER = ("import sys; sys.path.insert(0, sys.argv[1]); from aegis_cli.hooks.insights import main; "
                  "sys.exit(main(sys.argv[2:]))")


class UsageError(Exception):
    """A host or scope `aegis hook install --host` does not take (exit 2)."""


class ShapeError(InstallError):
    """A hooks file that parses but is not in the shape its host reads."""

    def __init__(self, path: Path, where: str, what: str):
        self.where, self.what = where, what
        super().__init__(f"{path}: '{where}' must be {what}; left unchanged. Fix the file, then re-run.")


@dataclass
class HookResult:
    host: str
    scope: str
    path: Optional[Path]
    status: str  # added | updated | unchanged | removed | absent | unavailable
    detail: str = ""
    dry_run: bool = False
    backup_dir: Optional[Path] = None
    rules_path: Optional[Path] = None
    rules_status: Optional[str] = None
    warnings: List[str] = field(default_factory=list)
    insight_capture: Optional[str] = None  # uninstall: removed | absent

    def as_dict(self) -> Dict[str, Any]:
        return {"host": self.host, "scope": self.scope, "path": None if self.path is None else str(self.path),
                "status": self.status, "detail": self.detail, "dry_run": self.dry_run,
                "backup_dir": None if self.backup_dir is None else str(self.backup_dir),
                "rules_path": None if self.rules_path is None else str(self.rules_path),
                "rules_status": self.rules_status,
                "tier": UNAVAILABLE if self.status == UNAVAILABLE else TIERS[self.host],
                "evidence": EVIDENCE[self.host], "warnings": list(self.warnings),
                "insight_capture": self.insight_capture}


# ── Where the files are ─────────────────────────────────────────────────────

def _windows() -> bool:
    return os.name == "nt"


def _env_dir(environ: Mapping[str, str], name: str) -> Optional[Path]:
    value = environ.get(name) or ""
    return Path(value) if value and os.path.isabs(value) else None


def _codex_home(home: Path, environ: Mapping[str, str]) -> Path:
    return _env_dir(environ, "CODEX_HOME") or home / ".codex"


def check_host(host: str) -> None:
    """Raise UsageError unless ``host`` takes a hook registration."""
    if host in HOOK_HOSTS:
        return
    try:
        spec = host_table.get(host)
    except KeyError:
        spec = None
    if spec is not None and spec.retired:
        raise UsageError(spec.retired)
    raise UsageError(f"--host {host!r} has no Aegis hooks; hook hosts: {', '.join(HOOK_HOSTS)}")


def hook_file(host: str, scope: str, *, home: Optional[Path], root: Optional[Path],
              environ: Mapping[str, str]) -> Optional[Path]:
    """The file that holds ``host``'s hooks at ``scope`` (None: project scope without a
    root, user scope without a home)."""
    check_host(host)
    if scope == "project":
        if root is None:
            return None
        rel = {"claude-code": (".claude", "settings.json"), "codex-cli": (".codex", "hooks.json"),
               "antigravity": (".agents", "hooks.json")}[host]
        return Path(root).joinpath(*rel)
    if home is None:
        return None
    if host == "claude-code":
        return (_env_dir(environ, "CLAUDE_CONFIG_DIR") or Path(home) / ".claude") / "settings.json"
    if host == "codex-cli":
        return _codex_home(Path(home), environ) / "hooks.json"
    return Path(home) / ".gemini" / "config" / "hooks.json"


def codex_rules_file(home: Path, environ: Mapping[str, str]) -> Path:
    return _codex_home(Path(home), environ) / "rules" / "aegis.rules"


# ── The aegis command ───────────────────────────────────────────────────────

def _scripts_dirs() -> List[str]:
    from aegis_cli import pathcheck

    return pathcheck.default_candidates()


def aegis_command(path: Optional[str] = None, scripts_dirs: Optional[Sequence[str]] = None,
                  outside: Optional[Union[str, Path]] = None) -> Optional[str]:
    """The absolute ``aegis`` a hook registration runs: the first in an absolute PATH entry
    outside ``outside`` (the repository, which could plant one), else the console script
    installed with this interpreter; None when neither exists."""
    from aegis_cli import pathcheck
    from aegis_core.pathlookup import which

    found = which("aegis", path, outside=outside)
    if found:
        return found
    dirs = _scripts_dirs() if scripts_dirs is None else list(scripts_dirs)
    directory = pathcheck.scripts_dir(dirs, cmd_name="aegis")
    if directory is None or not os.path.isabs(directory):
        return None
    for name in ("aegis.exe", "aegis") if _windows() else ("aegis",):
        candidate = os.path.join(directory, name)
        if os.path.isfile(candidate) and (_windows() or os.access(candidate, os.X_OK)):
            return candidate
    return None


def probe_hook_run(host: str, aegis: str, timeout: float = 20.0) -> None:
    """Raise InstallError unless ``aegis hook run pre-tool --host HOST`` exits 0 on an empty payload.

    An aegis older than 4.1 (an old copy earlier on PATH, or a downgrade) has no ``hook run``:
    argparse answers with exit 2, which Claude Code and Codex read as "block", so registering
    it would block every tool call. The handler itself exits 0 for any payload it cannot use.
    """
    proc = _probe([aegis, "hook", "run", "pre-tool", "--host", host], timeout)
    if proc.returncode != 0:
        detail = (proc.stderr or "").strip().splitlines()
        raise InstallError(
            f"{aegis} does not support `hook run` (exit {proc.returncode}"
            f"{': ' + detail[-1][:160] if detail else ''}). It is probably an older aegis than 4.1, and "
            f"{host} would read its exit code as a block on every tool call. Put the 4.1 aegis first on PATH "
            "(aegis --version), then re-run.")


def _probe(argv: List[str], timeout: float) -> Any:
    """Run ``argv`` with no input in an empty directory; InstallError when it cannot start."""
    import subprocess
    import tempfile

    try:
        with tempfile.TemporaryDirectory(prefix="aegis-hook-probe-") as empty:
            return subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                                  timeout=timeout, cwd=empty, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise InstallError(f"cannot run {argv[0]} to check it: {exc}") from exc


def unavailable_reason(host: str, aegis: Optional[str] = None) -> Optional[str]:
    """Why ``host``'s hook cannot be registered on this machine, or None."""
    if host == "antigravity" and _windows():
        return ("Antigravity hooks are unavailable on Windows: the shell agy runs hooks with there is "
                "unverified, and a wrong guess would block every tool call")
    if host == "codex-cli" and _windows() and aegis is not None and not AEGIS_PATH_CHARSET.fullmatch(aegis):
        return (f"Codex hooks are unavailable here: Codex runs them through %COMSPEC% /C and the aegis path "
                f"{aegis} is outside {_CHARSET_TEXT}")
    return None


def _check_aegis(host: str, aegis: str) -> None:
    if not os.path.isabs(aegis) and not PureWindowsPath(aegis).is_absolute():
        raise InstallError(f"the aegis path {aegis!r} is not absolute; a hook must name an absolute aegis")
    if host != "claude-code" and not AEGIS_PATH_CHARSET.fullmatch(aegis):
        raise InstallError(
            f"the aegis path {aegis} has characters outside {_CHARSET_TEXT}; {host} runs its hooks through a "
            "shell and Aegis does not quote paths for it. Install aegis under a plain path, then re-run.")


# ── The registration forms ──────────────────────────────────────────────────

def _handler_command(host: str, aegis: str) -> str:
    base = f"{aegis} hook run pre-tool --host {host}"
    if host == "antigravity":
        return f"{base} >/dev/null; [ $? -eq 75 ] && exit 1; exit 0"
    return base


def hook_group(host: str, aegis: str) -> Dict[str, Any]:
    """The exact PreToolUse group ``aegis hook install --host`` writes for ``host``."""
    check_host(host)
    if host == "claude-code":
        handler: Dict[str, Any] = {"type": "command", "command": aegis,
                                   "args": ["hook", "run", "pre-tool", "--host", host], "timeout": HOOK_TIMEOUT_S}
    else:
        handler = {"type": "command", "command": _handler_command(host, aegis), "timeout": HOOK_TIMEOUT_S}
    return {"matcher": MATCHERS[host], "hooks": [handler]}


def _is_aegis_path(token: Any) -> bool:
    """An absolute path (POSIX or Windows) whose file is aegis or aegis.exe."""
    return (isinstance(token, str) and (os.path.isabs(token) or PureWindowsPath(token).is_absolute())
            and PureWindowsPath(token).name.lower() in _AEGIS_NAMES)


def command_tokens(command: str) -> List[str]:
    """A hook command line split into words: POSIX quoting, except that a line with a
    backslash (a Windows path, which POSIX rules would eat) keeps its backslashes and only
    loses the quotes around a word. Unbalanced quotes split on whitespace."""
    try:
        if "\\" not in command:
            return shlex.split(command, posix=True)
        return [t.strip("\"'") for t in shlex.split(command, posix=False)]
    except ValueError:
        return command.split()


def handler_aegis(handler: Any) -> Optional[str]:
    """The absolute ``aegis`` a hook handler runs as ``<aegis> hook run ...`` (exec or
    shell form), or None when the handler is not an Aegis entry."""
    if not isinstance(handler, dict):
        return None
    command, args = handler.get("command"), handler.get("args")
    if isinstance(args, list) and args:
        return command if _is_aegis_path(command) and args[:2] == ["hook", "run"] else None
    if not isinstance(command, str):
        return None
    tokens = command_tokens(command)
    if len(tokens) >= 3 and _is_aegis_path(tokens[0]) and tokens[1:3] == ["hook", "run"]:
        return tokens[0]
    return None


def is_aegis_handler(handler: Any) -> bool:
    """Whether a hook handler runs ``<absolute aegis> hook run ...`` (exec or shell form)."""
    return handler_aegis(handler) is not None


#: The handler keys install writes (``args`` too: a shell form must not carry any).
_HANDLER_KEYS = ("type", "command", "args", "timeout")


def matches_install(host: str, group: Any, handler: Any) -> bool:
    """Whether an Aegis ``handler`` in ``group`` is what install writes for its own aegis
    path: the matcher, the type, the exec or shell form with its host, and the timeout.
    Keys install never writes do not count, so a host's own additions are not drift."""
    aegis = handler_aegis(handler)
    if aegis is None or not isinstance(group, dict):
        return False
    want = hook_group(host, aegis)
    return (group.get("matcher") == want["matcher"]
            and all(handler.get(key) == want["hooks"][0].get(key) for key in _HANDLER_KEYS))


#: (path of keys to a PreToolUse group list, group index, handler index, handler)
Located = Tuple[Tuple[str, ...], int, int, Dict[str, Any]]


def _event_lists(host: str, data: Dict[str, Any], path: Path,
                 strict: bool = False) -> List[Tuple[Tuple[str, ...], list]]:
    """Every PreToolUse group list of a hooks file, with its key path. ``strict`` refuses a
    shape the host would not load (what install would write into); otherwise such parts are
    skipped."""
    out: List[Tuple[Tuple[str, ...], list]] = []

    def bad(where: str, what: str) -> None:
        if strict:
            raise ShapeError(path, where, what)

    if host == "antigravity":
        containers = [((name,), value) for name, value in data.items()]
    else:
        containers = [(("hooks",), data["hooks"])] if "hooks" in data else []
    for keys, container in containers:
        if not isinstance(container, dict):
            if host != "antigravity" or keys == (AGY_GROUP,):
                bad(keys[0], "a JSON object")
            continue
        groups = container.get(EVENT)
        if groups is None:
            continue
        where = ".".join(keys + (EVENT,))
        if not isinstance(groups, list) or not all(isinstance(g, dict) for g in groups):
            bad(where, "a list of objects")
            continue
        for g in groups:
            if "hooks" in g and not isinstance(g["hooks"], list):
                bad(where + "[].hooks", "a list")
                break
        else:
            out.append((keys + (EVENT,), groups))
    return out


def aegis_handlers(host: str, data: Dict[str, Any], path: Path = Path("."), strict: bool = False) -> List[Located]:
    """Every Aegis handler in a hooks file's PreToolUse lists (any group, any position).
    ``strict`` refuses (ShapeError) a shape the host would not load; otherwise such parts
    are skipped."""
    found: List[Located] = []
    for keys, groups in _event_lists(host, data, path, strict):
        for gi, group in enumerate(groups):
            handlers = group.get("hooks")
            if not isinstance(handlers, list):
                continue
            for hi, handler in enumerate(handlers):
                if is_aegis_handler(handler):
                    found.append((keys, gi, hi, handler))
    return found


def _remove_aegis(host: str, data: Dict[str, Any], path: Path) -> Optional[Tuple[Tuple[str, ...], int]]:
    """Drop every Aegis handler (and groups left empty) from a file aegis_handlers(strict=True)
    accepted; where the first group with one was, or None when there was none."""
    first: Optional[Tuple[Tuple[str, ...], int]] = None
    for keys, groups in _event_lists(host, data, path):
        kept: List[Any] = []
        for group in groups:
            handlers = group.get("hooks")
            if isinstance(handlers, list) and any(is_aegis_handler(h) for h in handlers):
                rest = [h for h in handlers if not is_aegis_handler(h)]
                if rest:
                    kept.append(dict(group, hooks=rest))
                # A shared group keeps its index (another hook's Codex trust covers its
                # position too); Aegis's own group goes right after it.
                if first is None:
                    first = (keys, len(kept))
                continue
            kept.append(group)
        groups[:] = kept
    return first


def _container_path(host: str) -> Tuple[str, ...]:
    return (AGY_GROUP, EVENT) if host == "antigravity" else ("hooks", EVENT)


def _drop_empty(host: str, data: Dict[str, Any]) -> None:
    """Remove the containers Aegis's removal left empty; nothing else."""
    top = AGY_GROUP if host == "antigravity" else "hooks"
    names = list(data) if host == "antigravity" else [top]
    for name in names:
        container = data.get(name)
        if isinstance(container, dict) and container.get(EVENT) == []:
            del container[EVENT]
            if not container and (host != "antigravity" or name == AGY_GROUP):
                del data[name]


# ── Safe writes ─────────────────────────────────────────────────────────────

def _serialize(data: Dict[str, Any]) -> bytes:
    return plane._dump(data)


def _load(path: Path) -> Tuple[Optional[bytes], Dict[str, Any]]:
    return plane._load_json_object(path)


def _backup(path: Path, raw: bytes, backup: Path, dry_run: bool) -> None:
    copy = backup / path.name
    plane._writable_dir(copy, creating=True)
    if dry_run:
        return
    try:
        plane.private_dirs(backup)
        atomic_write_bytes(copy, raw, mode=0o600)
    except OSError as exc:
        raise InstallError(f"{path}: cannot back it up to {backup} ({exc.strerror or exc}); left unchanged") from exc


def _restore(path: Path, raw: Optional[bytes]) -> None:
    try:
        if raw is None:
            os.unlink(path)
        else:
            atomic_write_bytes(path, raw)
    except OSError:
        pass


def _write_json(path: Path, raw: Optional[bytes], data: Dict[str, Any], backup: Path, dry_run: bool,
                check: Any = None) -> None:
    """Back up, replace atomically, then re-read: a file that does not parse back to what
    was meant is replaced by its old bytes (or removed when it was new)."""
    payload = _serialize(data)
    plane._preflight(path, raw)
    if raw is not None:
        _backup(path, raw, backup, dry_run)
    if dry_run:
        return
    plane._replace(path, raw, payload)
    try:
        written = path.read_bytes()
        reread = plane.strict_loads(written.decode("utf-8"))
        ok = reread == data
    except (OSError, ValueError, UnicodeDecodeError, RecursionError):
        ok = False
    if not ok:
        _restore(path, raw)
        raise InstallError(f"{path}: did not re-read as the JSON Aegis meant to write; the previous bytes were "
                           "put back. Report this, then re-run.")


def edit_hook_file(path: Union[str, Path], edit: Callable[[Dict[str, Any]], Any], *, home: Union[str, Path],
                   scope: str = "user") -> Optional[Path]:
    """Apply ``edit`` to a hooks file under the host-plane contract (refuse, back up, replace,
    re-read); a ValueError from ``edit`` refuses. The backup directory, or None when none."""
    path = Path(path)
    raw, data = _load(path)
    before = copy.deepcopy(data)
    try:
        edit(data)
    except ValueError as exc:
        raise InstallError(f"{path}: {exc}; left unchanged") from exc
    if data == before:
        return None
    backup = plane.backup_dir(home)
    _write_json(path, raw, data, backup / scope, False)
    return backup if raw is not None else None


def install_insight_hook(host: str, excerpts: bool, *, home: Optional[Union[str, Path]],
                         environ: Mapping[str, str]) -> Dict[str, Any]:
    """Register the UserPromptSubmit insight hook, running this interpreter on this aegis_cli,
    in ``host``'s user hooks file, then create ~/.aegis/link.key. A refusal writes nothing."""
    from aegis_core import insights
    from aegis_core.workspace.layout import UserLayout

    if host not in insights.SUPPORTED_INSIGHT_HOSTS:
        raise ValueError(f"unsupported host {host!r} for insight hook; supported: {list(insights.SUPPORTED_INSIGHT_HOSTS)}")
    if host == "codex-cli" and _windows():
        raise InstallError("Codex insight capture is unavailable on Windows: Codex runs hooks through %COMSPEC% /C, "
                           "which cannot take the quoted -c program the hook needs; nothing was written")
    layout = UserLayout(Path(home)) if home is not None else UserLayout.current()
    python, root = sys.executable or "", aegis_import_root()
    if layout is None or not os.path.isabs(python) or not os.path.isabs(root):
        raise OSError(f"the insight hook needs a home directory and an absolute interpreter and import root "
                      f"(interpreter {python!r}, import root {root!r}); nothing was written")
    argv = [python, "-I", "-c", INSIGHT_RUNNER, root, "--host", host, "--excerpts" if excerpts else "--no-excerpts"]
    handler: Dict[str, Any] = {"type": "command", "command": python, "args": argv[1:]}
    if host == "codex-cli":
        handler = {"type": "command", "command": shlex.join(argv)}
    # Import only: running the hook on an empty payload would record a heartbeat.
    proc = _probe([python, "-I", "-c", "import sys; sys.path.insert(0, sys.argv[1]); import aegis_cli.hooks.insights",
                   root], 20.0)
    if proc.returncode != 0:
        raise InstallError(f"{python} cannot import aegis_cli.hooks.insights from {root} (exit {proc.returncode}); "
                           "nothing was written")
    path = hook_file(host, "user", home=layout.home, root=None, environ=environ)
    used = edit_hook_file(path, lambda data: insights.merge_insight_hook(data, handler), home=layout.home)  # type: ignore[arg-type]
    insights.create_link_key(layout.home)
    return {"host": host, "status": "enabled_excerpts" if excerpts else "enabled_counters_only",
            "excerpts": bool(excerpts), "config_path": str(path), "command": handler["command"],
            "backup_dir": None if used is None else str(used)}


def codex_rules_text() -> str:
    """``aegis.rules``: one forbidden ``prefix_rule`` per BLOCK_SET Codex prefix."""
    # Imported here: every aegis command builds the hook parser, which reads this module.
    from aegis_core import command_safety

    parts = [CODEX_RULES_HEADER, "# Do not edit: aegis rewrites it; aegis hook uninstall --host codex-cli removes it.\n"]
    for rule in command_safety.BLOCK_SET:
        for prefix in rule.codex_prefixes:
            pattern = json.dumps([list(p) if isinstance(p, tuple) else p for p in prefix])
            parts.append(
                "\nprefix_rule(\n"
                f"    pattern = {pattern},\n"
                '    decision = "forbidden",\n'
                f"    justification = {json.dumps('aegis: ' + rule.reason)},\n"
                ")\n")
    return "".join(parts)


def _rules_state(path: Path) -> Tuple[Optional[bytes], bool]:
    """(current bytes or None, whether Aegis wrote them); refuses links and specials."""
    raw = plane._read(path)
    return raw, raw is not None and raw.startswith(CODEX_RULES_HEADER.encode("utf-8"))


def _plan_rules(path: Path) -> Tuple[Optional[bytes], str]:
    raw, ours = _rules_state(path)
    want = codex_rules_text().encode("utf-8")
    if raw is not None and not ours:
        raise InstallError(f"{path}: exists and was not written by Aegis; left unchanged. Move it aside, then "
                           "re-run (Aegis never edits your own Codex rules).")
    if raw == want:
        return raw, "unchanged"
    plane._preflight(path, raw)
    return raw, "updated" if raw is not None else "added"


# ── Install / uninstall ─────────────────────────────────────────────────────

def _same_dir(a: Path, b: Path) -> bool:
    try:
        return os.path.samefile(a, b)
    except OSError:
        return os.path.normcase(os.path.abspath(a)) == os.path.normcase(os.path.abspath(b))


def _other_scope_has_entry(host: str, scope: str, home: Path, root: Optional[Path],
                           environ: Mapping[str, str]) -> Optional[Path]:
    other = "project" if scope == "user" else "user"
    if other == "project" and (root is None or _same_dir(root, home)):
        return None
    path = hook_file(host, other, home=home, root=root, environ=environ)
    if path is None:
        return None
    try:
        _, data = _load(path)
    except InstallError as exc:
        raise InstallError(f"cannot tell whether {host} already has an Aegis hook at {other} scope: {exc}") from exc
    return path if aegis_handlers(host, data, path) else None


def install(host: str, scope: str = "user", *, home: Union[str, Path], root: Optional[Union[str, Path]],
            aegis: str, environ: Mapping[str, str], dry_run: bool = False) -> HookResult:
    """Register ``host``'s PreToolUse hook at ``scope``. Raises UsageError for a host
    without hooks or an unknown scope, InstallError when a file cannot be changed safely
    (nothing is written then)."""
    check_host(host)
    if scope not in SCOPES:
        raise UsageError(f"--scope must be one of {', '.join(SCOPES)}")
    home = Path(home)
    root = None if root is None else Path(root)
    why = unavailable_reason(host, aegis)
    if why:
        return HookResult(host, scope, None, UNAVAILABLE, why, dry_run)
    _check_aegis(host, aegis)
    if scope == "project" and (root is None or _same_dir(root, home)):
        raise InstallError("--scope project needs a repository: here the workspace is your home directory, "
                           "whose host files are the user scope")
    path = hook_file(host, scope, home=home, root=root, environ=environ)
    assert path is not None
    clash = _other_scope_has_entry(host, scope, home, root, environ)
    if clash is not None:
        other = "project" if scope == "user" else "user"
        raise InstallError(f"{host} already has an Aegis hook at {other} scope ({clash}); a second one would run "
                           f"the handler twice. Run aegis hook uninstall --host {host} --scope {other} first.")
    raw, data = _load(path)
    want = hook_group(host, aegis)
    located = aegis_handlers(host, data, path, strict=True)
    container = _container_path(host)
    current = _get_list(data, container)
    if (len(located) == 1 and located[0][0] == container and current is not None
            and current[located[0][1]] == want):
        status = "unchanged"
    else:
        first = _remove_aegis(host, data, path)
        status = "updated" if first is not None else "added"
        groups = _ensure_list(data, container, path)
        index = first[1] if first is not None and first[0] == container else len(groups)
        groups.insert(index, want)
    rules_path = codex_rules_file(home, environ) if host == "codex-cli" else None
    rules_raw, rules_status = _plan_rules(rules_path) if rules_path is not None else (None, None)
    backup: Optional[Path] = None
    if status != "unchanged" or rules_status not in (None, "unchanged"):
        backup = plane.backup_dir(home)
    if status != "unchanged":
        _write_json(path, raw, data, backup / scope, dry_run)  # type: ignore[operator]
    if rules_path is not None and rules_status != "unchanged":
        if rules_raw is not None:
            _backup(rules_path, rules_raw, backup / "user", dry_run)  # type: ignore[operator]
        if not dry_run:
            plane._replace(rules_path, rules_raw, codex_rules_text().encode("utf-8"))
    used = backup if backup is not None and backup.exists() else None
    result = HookResult(host, scope, path, status, "", dry_run, used, rules_path, rules_status)
    if host == "codex-cli":
        result.warnings.append(CODEX_TRUST_STEP)
    if scope == "project":
        result.warnings.append(
            f"{path} is a repository file: once committed, your teammates' {host} will execute this hook "
            "(the aegis path in it is this machine's). Commit it only if that is intended.")
    return result


def _get_list(data: Dict[str, Any], keys: Tuple[str, ...]) -> Optional[list]:
    node: Any = data
    for key in keys:
        node = node.get(key) if isinstance(node, dict) else None
    return node if isinstance(node, list) else None


def _ensure_list(data: Dict[str, Any], keys: Tuple[str, ...], path: Path) -> list:
    node: Any = data
    for key in keys[:-1]:
        child = node.setdefault(key, {})
        if not isinstance(child, dict):
            raise InstallError(f"{path}: '{key}' must be a JSON object; left unchanged")
        node = child
    groups = node.setdefault(keys[-1], [])
    if not isinstance(groups, list):
        raise InstallError(f"{path}: '{'.'.join(keys)}' must be a list; left unchanged")
    return groups


def _rules_still_used(host: str, covered: Sequence[str], home: Path, root: Optional[Path],
                      environ: Mapping[str, str]) -> Optional[str]:
    """Why the Codex rules file stays once the entries at ``covered`` are gone: an Aegis
    Codex hook at another scope still uses it, or that scope's file cannot tell."""
    for other in SCOPES:
        if other in covered or (other == "project" and (root is None or _same_dir(root, home))):
            continue
        path = hook_file(host, other, home=home, root=root, environ=environ)
        assert path is not None
        try:
            _, data = _load(path)
        except InstallError as exc:
            return f"cannot tell whether a {other}-scope hook uses it: {exc}"
        if aegis_handlers(host, data, path):
            return f"the Aegis hook at {other} scope ({path}) still uses it"
    return None


def uninstall(host: str, scope: Optional[str] = None, *, home: Union[str, Path], root: Optional[Union[str, Path]],
              environ: Mapping[str, str], dry_run: bool = False) -> List[HookResult]:
    """Remove Aegis's hook entries for ``host`` at ``scope`` (both scopes when None), and
    for Codex the aegis.rules Aegis wrote once no Aegis Codex hook is left at any scope.
    Everything else in the files stays. Every file is read and checked before the first
    is written, so a refusal writes nothing."""
    from aegis_core.insights import remove_insight_hook

    check_host(host)
    if scope is not None and scope not in SCOPES:
        raise UsageError(f"--scope must be one of {', '.join(SCOPES)}")
    home = Path(home)
    root = None if root is None else Path(root)
    results: List[HookResult] = []
    writes: List[Tuple[str, Path, Optional[bytes], Dict[str, Any]]] = []
    for each in [scope] if scope else list(SCOPES):
        if each == "project" and (root is None or _same_dir(root, home)):
            if scope == "project":
                raise InstallError("--scope project needs a repository: here the workspace is your home directory")
            continue
        path = hook_file(host, each, home=home, root=root, environ=environ)
        assert path is not None
        raw, data = _load(path)
        status = "absent"
        if raw is not None and aegis_handlers(host, data, path, strict=True):
            _remove_aegis(host, data, path)
            _drop_empty(host, data)
            status = "removed"
        # The insight capture hook `aegis rule insight enable` wrote goes too.
        insight = "removed" if raw is not None and remove_insight_hook(host, data) else "absent"
        if "removed" in (status, insight):
            plane._preflight(path, raw)
            writes.append((each, path, raw, data))
        results.append(HookResult(host, each, path, status, "", dry_run, insight_capture=insight))
    remove_rules: Optional[Path] = None
    rules_raw: Optional[bytes] = None
    if host == "codex-cli":
        rules = codex_rules_file(home, environ)
        rules_raw, ours = _rules_state(rules)
        rules_status, why = "absent", ""
        if rules_raw is not None and not ours:
            rules_status = "not_aegis"
        elif rules_raw is not None:
            why = _rules_still_used(host, [r.scope for r in results], home, root, environ) or ""
            if why:
                rules_status = "kept"
            else:
                plane._preflight(rules, rules_raw)
                rules_status, remove_rules = "removed", rules
        # results is never empty: only the project scope is ever skipped, and only with both.
        results[0].rules_path, results[0].rules_status, results[0].detail = rules, rules_status, why
    backup = plane.backup_dir(home) if writes or remove_rules is not None else None
    done: List[str] = []
    try:
        for each, path, raw, data in writes:
            _write_json(path, raw, data, backup / each, dry_run)  # type: ignore[operator]
            done.append(str(path))
        if remove_rules is not None:
            _backup(remove_rules, rules_raw, backup / "user", dry_run)  # type: ignore[arg-type,operator]
            if not dry_run:
                plane._preflight(remove_rules, rules_raw)
                try:
                    os.unlink(remove_rules)
                except OSError as exc:
                    raise InstallError(f"{remove_rules}: cannot be removed ({exc.strerror or exc}); "
                                       "left in place") from exc
    except InstallError as exc:
        if done:
            raise InstallError(f"{str(exc).rstrip('.')}. The Aegis hook was already removed from {', '.join(done)} "
                               f"(backup in {backup}).") from exc
        raise
    used = backup if backup is not None and backup.exists() else None
    for result in results:
        result.backup_dir = used
    return results


# ── CLI ─────────────────────────────────────────────────────────────────────

def _hook_payload(command: str, host: str, scope: Optional[str], root: Optional[Path],
              results: List[HookResult]) -> Dict[str, Any]:

    return {**primitives.envelope(f"aegis hook {command}", {"host": host, "scope": scope, "workspace": None if root is None else str(root)}),
            "results": [r.as_dict() for r in results]}


def _context(args: Any) -> Tuple[Path, Optional[Path]]:
    from aegis_core.workspace.layout import UserLayout

    layout = UserLayout.current()
    if layout is None:
        raise InstallError("no home directory: Aegis cannot find the host config files")
    ws = getattr(args, "ws", None)  # `aegis hook` always runs in a workspace (cli._attach_workspace)
    return Path(layout.home), None if ws is None else Path(ws.root).resolve()


def _print_text(command: str, results: List[HookResult]) -> None:
    for r in results:
        where = r.path if r.path is not None else "-"
        verb = {"added": "added to", "updated": "updated in", "unchanged": "already current in",
                "removed": "removed from", "absent": "not found in"}.get(r.status)
        prefix = "(dry run) " if r.dry_run else ""
        if r.status == UNAVAILABLE:
            print(f"➖ {r.host}: hooks unavailable: {r.detail}")
            continue
        icon = "ℹ️ " if r.status in ("absent", "unchanged") else "✅"
        print(f"{icon} {prefix}{r.host}: the Aegis PreToolUse hook {verb} {where} ({r.scope} scope)")
        if r.insight_capture == "removed":
            print(f"   the Aegis insight capture hook (UserPromptSubmit) removed from {where}")
        if r.rules_status:  # set exactly when the result has a Codex rules file
            why = f" ({r.detail})" if r.rules_status == "kept" else ""
            print(f"   Codex rules {r.rules_path}: {r.rules_status.replace('_', ' ')}{why}")
        if command == "install":
            print(f"   tier: {TIERS[r.host]} [{EVIDENCE[r.host]}]; doctor cannot confirm the host runs it")
        if r.backup_dir is not None:
            print(f"   backup: {r.backup_dir}")
        for warning in r.warnings:
            if "teammates" in warning:
                print(f"⚠️  {warning}", file=sys.stderr)
            else:
                print(f"   Next: {warning}")


def _run(command: str, args: Any) -> int:
    host, scope = str(args.host), getattr(args, "scope", None)
    try:  # a surface name (codex-app, claude-desktop-code, ...) names its host's config plane
        host = host_table.resolve(host)
    except KeyError:
        pass  # check_host below says which hosts take hooks
    use_json, dry_run = bool(getattr(args, "json", False)), bool(getattr(args, "dry_run", False))
    try:
        check_host(host)
        if scope is not None and scope not in SCOPES:
            raise UsageError(f"--scope must be one of {', '.join(SCOPES)}")
        home, root = _context(args)
        if command == "install":
            aegis = aegis_command(os.environ.get("PATH", ""), outside=root)
            if aegis is None:
                why = unavailable_reason(host)
                if why:
                    results = [HookResult(host, scope or "user", None, UNAVAILABLE, why, dry_run)]
                else:
                    raise InstallError("no absolute aegis command found (not on an absolute PATH entry outside the "
                                       "repository, nor beside this Python): install aegis, then re-run")
            else:
                probe_hook_run(host, aegis)
                results = [install(host, scope or "user", home=home, root=root, aegis=aegis, environ=os.environ,
                                   dry_run=dry_run)]
        else:
            results = uninstall(host, scope, home=home, root=root, environ=os.environ, dry_run=dry_run)
    except UsageError as exc:
        print(f"aegis hook {command}: {exc}", file=sys.stderr)
        return 2
    except InstallError as exc:
        print(f"❌ aegis hook {command} --host {host}: {exc}", file=sys.stderr)
        return 1
    if use_json:
        print(json.dumps(_hook_payload(command, host, scope or ("user" if command == "install" else None), root,
                                   results), indent=2))
        for r in results:
            for warning in r.warnings:
                if "teammates" in warning:
                    print(f"⚠️  {warning}", file=sys.stderr)
    else:
        _print_text(command, results)
    return 1 if any(r.status == UNAVAILABLE for r in results) else 0


def run_host_install(args: Any) -> int:
    """`aegis hook install --host <h> [--scope user|project] [--dry-run] [--json]`."""
    return _run("install", args)


def run_host_uninstall(args: Any) -> int:
    """`aegis hook uninstall --host <h> [--scope user|project] [--dry-run] [--json]`."""
    return _run("uninstall", args)
