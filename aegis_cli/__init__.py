"""Aegis CLI — user-facing governance commands."""
from __future__ import annotations

import re
from pathlib import Path

from aegis_core._version import __version__ as __version__


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


def sanitize_display(text: str, max_len: int = 80) -> str:
    """Strip ANSI escapes, C1 control chars, and DCS/OSC sequences for safe terminal display."""
    text = re.sub(r'\x1b(?:\[[0-9;?]*[a-zA-Z]|\].*?(?:\x07|\x1b\\)|P.*?(?:\x1b\\|\x07)|[=><NOM78c])', '', text)
    text = re.sub(r'[\x00-\x08\x0b-\x1f\x7f]', '', text)
    text = re.sub(r'[\x80-\x9f]', '', text)
    text = text.replace('\n', ' ').replace('\r', '')
    text = text.replace('\t', ' ')
    if len(text) > max_len:
        text = text[:max_len - 3] + '...'
    return text


__all__ = [
    "NO_HOME_MESSAGE",
    "resolve_root",
    "sanitize_display",
]
