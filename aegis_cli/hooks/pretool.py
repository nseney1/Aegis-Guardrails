"""`aegis hook run pre-tool --host <h>`: one PreToolUse handler for Claude Code, Codex CLI
and Antigravity (v4.1 spec §2, AD-8 honest tiers).

Contract, on every host:

- stdin: the host's PreToolUse payload (JSON). stdout: never written.
- exit 0 allows. So does every internal error, the DEADLINE_SECONDS deadline, an unusable
  or oversized payload, an unknown host or event, and an ungoverned workspace: the hooks
  are registered at user scope and fire in every repository, and **fail-open is the
  design** (they are guardrails, not a security boundary).
- exit 2 blocks on Claude Code and Codex CLI, with the reason on stderr.
- exit 75 blocks on Antigravity. Its registration wrapper maps 75 to 1 (agy blocks on a
  non-zero exit) and every other code to 0.

The workspace comes from the payload, through the AD-4 resolver aegis-mcp binds with
(``resolve_binding``: nearest ``.aegis/`` within the git boundary, never ``$HOME``): Claude
``CLAUDE_PROJECT_DIR`` (host-attested) then ``cwd``, Codex ``cwd``, agy
``workspacePaths[0]``; an ``AEGIS_WORKSPACE`` pin in the hook's environment and the
registry take part as they do for the server. Edited paths are confined under that root;
a path outside it is not gated.

1. **Scan-before-edit** (edit tools): the edit passes when one ``scan`` row of the
   activity log, from any host or session (``aegis scan``'s host ``cli`` included), names
   every edited path within ``jit.scan_window_s``. Otherwise Claude and Codex exit 2 with
   ``aegis: call aegis_scan with <paths> before editing (or run: aegis scan <paths>)``;
   agy only records (exit 0, no output). Files under the workspace's rules directory
   (``.aegis/rules/``) are only recorded on every host: one broken rule file makes every
   scan fail closed and write no row, so blocking its repair would block every edit for
   good.
2. **Destructive-command guard** (shell tools): ``command_safety.classify_command``. A
   BLOCK_SET match blocks (2, or 75 on agy) with its reason on stderr; a RECORD_SET match
   is recorded and runs.

Each outcome appends an events-log row: ``scan_gate{result: pass|block|record}`` or
``guard_match{tier, action, rule}``. A failed append never changes the decision.
"""
from __future__ import annotations

from contextlib import contextmanager, redirect_stdout
from dataclasses import dataclass, field
from datetime import datetime
import io
import json
import os
from pathlib import Path, PurePath
import shlex
import signal
import sys
import time
from types import SimpleNamespace
from typing import Any, BinaryIO, Dict, Iterator, List, Mapping, Optional, Sequence, Union

from aegis_core import command_safety, events, hook_events, scan_compliance
from aegis_core.config import env_workspace, scan_window_s
from aegis_core.workspace.binding import Attested, read_registry, resolve_binding
from aegis_core.workspace.confinement import confine_path_internal
from aegis_core.workspace.layout import WorkspaceLayout

__all__ = [
    "DEADLINE_SECONDS",
    "EVENTS",
    "EXIT_AGY_BLOCK",
    "EXIT_ALLOW",
    "EXIT_BLOCK",
    "MAX_PAYLOAD_BYTES",
    "run_hook_argv",
    "run_hook_run",
    "run_pre_tool",
]

EVENTS = ("pre-tool",)
EXIT_ALLOW, EXIT_BLOCK, EXIT_AGY_BLOCK = 0, 2, 75
# Every host's registration allows 10 s; finishing well inside it keeps a host from
# killing the hook, which agy would read as a block.
DEADLINE_SECONDS = 5.0
MAX_PAYLOAD_BYTES = 32 * 1024 * 1024
_AGY = "antigravity"


class _Deadline(BaseException):
    """SIGALRM at the deadline; caught like every other error (exit 0)."""


def _expire(signum: int, frame: Any) -> None:
    raise _Deadline()


@contextmanager
def _deadline(seconds: float) -> Iterator[None]:
    """Raise _Deadline after ``seconds``, then restore the caller's SIGALRM handler and
    timer. Without SIGALRM (Windows) or off the main thread there is no internal
    deadline and the host's hook timeout is the bound (no thread is started)."""
    try:
        previous = signal.signal(signal.SIGALRM, _expire)
    except (AttributeError, ValueError):
        yield
        return
    started = time.monotonic()
    old_delay, old_interval = signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous if previous is not None else signal.SIG_DFL)
        if old_delay:
            left = old_delay - (time.monotonic() - started)
            signal.setitimer(signal.ITIMER_REAL, max(left, 0.001), old_interval)


@dataclass(frozen=True)
class _Decision:
    code: int = EXIT_ALLOW
    message: str = ""
    root: Optional[Path] = None
    event: str = ""
    result: str = ""
    detail: Dict[str, Any] = field(default_factory=dict)


_ALLOW = _Decision()


def _root(call: hook_events.HookCall, environ: Mapping[str, str]) -> Optional[Path]:
    """The governed root of the call, as aegis-mcp would bind it, or None."""
    attested = []
    if call.workspace_source == "claude_project_dir" and call.workspace:
        attested.append(Attested("claude_project_dir", call.workspace))
    binding = resolve_binding(
        pin=env_workspace(environ),
        attested=attested,
        files=[p for p in call.paths if os.path.isabs(p)],
        cwd=None if attested else call.workspace,
        registry=read_registry(),
    )
    return binding.root if binding.bound else None


def _guard(call: hook_events.HookCall, environ: Mapping[str, str]) -> _Decision:
    rule = command_safety.classify_command(call.command)
    if rule is None:
        return _ALLOW
    root = _root(call, environ)
    if root is None:
        return _ALLOW
    detail = {"tier": rule.tier, "action": rule.tier, "rule": rule.id}
    if rule.tier != command_safety.GUARD_BLOCK:
        return _Decision(root=root, event="guard_match", result=rule.tier, detail=detail)
    code = EXIT_AGY_BLOCK if call.host == _AGY else EXIT_BLOCK
    message = f"aegis: blocked {rule.id}: {rule.reason}. If it is intended, ask the user to run it."
    return _Decision(code, message, root, "guard_match", command_safety.GUARD_BLOCK, detail)


def _scan_gate(call: hook_events.HookCall, environ: Mapping[str, str], now: Optional[datetime]) -> _Decision:
    root = _root(call, environ)
    if root is None:
        return _ALLOW
    edited: List[str] = []
    for path in call.paths:
        try:
            edited.append(PurePath(confine_path_internal(root, path)[1]).as_posix())
        except ValueError:  # outside the governed root, or unresolvable: not gated
            continue
    edited = list(dict.fromkeys(edited))
    if not edited:
        return _ALLOW
    detail = {"paths": len(edited)}
    window = scan_window_s(root)
    if scan_compliance.scan_covers(root, edited, window, now):
        return _Decision(root=root, event="scan_gate", result="pass", detail=detail)
    rules = PurePath(os.path.relpath(WorkspaceLayout(root).rules_dir, root)).as_posix() + "/"
    gated = [p for p in edited if not p.startswith(rules)]
    # Exit 0 with stderr has no visible effect on agy (LIVE); a visible deny waits for a
    # probe. A rule file stays editable: a broken one makes every scan fail closed. When no
    # rule file is among the edited paths the log was just asked about these very paths.
    if call.host == _AGY or not gated or (
            len(gated) < len(edited) and scan_compliance.scan_covers(root, gated, window, now)):
        return _Decision(root=root, event="scan_gate", result="record", detail=detail)
    shown = " ".join(shlex.quote(p) for p in gated)
    message = f"aegis: call aegis_scan with {shown} before editing (or run: aegis scan {shown})"
    return _Decision(EXIT_BLOCK, message, root, "scan_gate", "block", detail)


def _decide(host: str, data: bytes, environ: Mapping[str, str], now: Optional[datetime]) -> _Decision:
    if host not in hook_events.HOSTS or len(data) > MAX_PAYLOAD_BYTES:
        return _ALLOW
    try:
        payload = json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return _ALLOW
    call = hook_events.normalize(host, payload, environ)
    if call is None:
        return _ALLOW
    if call.kind == hook_events.KIND_SHELL:
        guard_decision = _guard(call, environ)
        if guard_decision.code != EXIT_ALLOW or not call.paths:
            return guard_decision
        scan_decision = _scan_gate(call, environ, now)
        if scan_decision.code != EXIT_ALLOW:
            return scan_decision
        return guard_decision if guard_decision.event else scan_decision
    if call.kind == hook_events.KIND_EDIT and call.paths:
        return _scan_gate(call, environ, now)
    return _ALLOW


def run_pre_tool(
    host: str,
    payload: Union[bytes, BinaryIO],
    environ: Mapping[str, str],
    now: Optional[datetime] = None,
) -> int:
    """Decide one PreToolUse call from ``host``; return the exit code (see the module
    docstring). ``payload`` is the stdin bytes, or a binary stream read under the
    deadline (at most MAX_PAYLOAD_BYTES + 1 bytes). ``now`` is the scan window's clock
    (UTC; the current time when None). Writes only the block reason to stderr and the
    event row; never raises."""
    try:
        with _deadline(DEADLINE_SECONDS), redirect_stdout(io.StringIO()):
            try:
                data = payload if isinstance(payload, bytes) else payload.read(MAX_PAYLOAD_BYTES + 1)
                decision = _decide(host, data, environ, now)
            except BaseException:
                return EXIT_ALLOW
            try:
                if decision.message:
                    sys.stderr.write(decision.message + "\n")
                    sys.stderr.flush()
                if decision.event:
                    events.append(decision.root, decision.event, decision.result, decision.detail, host=host)
            except BaseException:  # unlike CLI metrics, a hook must not interrupt its host
                pass  # telemetry and the reason text never change the decision
            return decision.code
    except BaseException:
        return EXIT_ALLOW


def run_hook_argv(argv: Sequence[str]) -> int:
    """`aegis hook run [EVENT] [--host HOST | --host=HOST]` as the host registrations call
    it: ``cli.main`` dispatches here before it builds its parser or attaches a workspace
    (user-scope hooks fire from any cwd, $HOME included; the workspace comes from the
    payload). Arguments of any other shape exit 0 silently: argparse's usage error exits 2,
    which Claude Code and Codex read as a block. Never raises."""
    try:
        event = host = None
        words = list(argv)
        while words:
            word = words.pop(0)
            if word == "--host" and words and host is None:
                host = words.pop(0)
            elif word.startswith("--host=") and host is None:
                host = word[len("--host="):]
            elif not word.startswith("-") and event is None:
                event = word
            else:
                return EXIT_ALLOW
        return run_hook_run(SimpleNamespace(event=event, host=host))
    except BaseException:
        return EXIT_ALLOW


def run_hook_run(args: Any) -> int:
    """`aegis hook run <event> --host <h>` from parsed arguments: the payload is on stdin.
    Never raises."""
    try:
        if getattr(args, "event", None) not in EVENTS:
            return EXIT_ALLOW
        stdin = getattr(sys.stdin, "buffer", None)
        if stdin is None:
            return EXIT_ALLOW
        return run_pre_tool(str(getattr(args, "host", None) or ""), stdin, os.environ)
    except BaseException:
        return EXIT_ALLOW
