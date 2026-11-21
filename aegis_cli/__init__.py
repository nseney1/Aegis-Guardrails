"""Aegis CLI — user-facing governance commands."""
from __future__ import annotations

import sys
from pathlib import Path

from aegis_core._version import __version__ as __version__
from aegis_core.primitives import aegis_import_root as aegis_import_root
from aegis_core.primitives import sanitize_display as sanitize_display


NO_HOME_MESSAGE = "no home directory can be resolved on this machine (set HOME, or USERPROFILE on Windows)"


def resolve_root(args, default=None):
    """Resolve project/repo root from args, checking ws then workspace."""
    if hasattr(args, "ws") and getattr(args, "ws", None) is not None:
        return args.ws.root
    for attr in ('workspace', 'repo_root', 'project_root', '_root', '_project_root'):
        val = getattr(args, attr, None)
        if val:
            return Path(val)
    return default if default is not None else Path.cwd()


def stdin_is_tty() -> bool:
    try:
        return bool(sys.stdin.isatty())
    except (AttributeError, ValueError, OSError):
        return False


__all__ = [
    "stdin_is_tty",
    "aegis_import_root",
    "NO_HOME_MESSAGE",
    "resolve_root",
    "sanitize_display",
]
