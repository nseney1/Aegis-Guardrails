"""Aegis CLI — user-facing governance commands."""
from __future__ import annotations

import re
import sys
from typing import Optional
from pathlib import Path

from aegis_core._version import __version__ as __version__
from aegis_core.primitives import aegis_import_root as aegis_import_root


NO_HOME_MESSAGE = "no home directory can be resolved on this machine (set HOME, or USERPROFILE on Windows)"
_DISPLAY_CONTROLS = re.compile(r'[\x00-\x1f\x7f-\x9f]')


def resolve_root(args, default=None):
    """Resolve project/repo root from args, checking ws then workspace."""
    if hasattr(args, "ws") and getattr(args, "ws", None) is not None:
        return args.ws.root
    for attr in ('workspace', 'repo_root', 'project_root', '_root', '_project_root'):
        val = getattr(args, attr, None)
        if val:
            return Path(val)
    return default if default is not None else Path.cwd()


def sanitize_display(text: object, max_len: Optional[int] = 80) -> str:
    """Strip supported ANSI escapes and controls in linear time, then truncate.

    A newline or end-of-input abandons an unterminated OSC/DCS string, preserving
    its printable text. Each span is inspected at most twice, even with nested
    unterminated introducers. Plain text bypasses the character loop.
    """
    text = str(text)
    first_control = _DISPLAY_CONTROLS.search(text)
    if first_control is None:
        return text[:max_len - 3] + '...' if max_len is not None and len(text) > max_len else text
    index = first_control.start()
    shown = [text[:index]]
    size = len(text)
    literal_until = 0
    while index < size:
        char = text[index]
        if char == '\x1b' and index + 1 < size:
            kind = text[index + 1]
            if kind in (']', 'P') and index >= literal_until:
                end = index + 2
                while end < size and text[end] != '\n':
                    if text[end] == '\x07':
                        index = end + 1
                        break
                    if text[end] == '\x1b' and end + 1 < size and text[end + 1] == '\\':
                        index = end + 2
                        break
                    end += 1
                else:
                    # No string beginning before this boundary can terminate.
                    # Render that span normally without rescanning its suffixes.
                    literal_until = end
                    shown.append(kind)
                    index += 2
                continue
            if kind == '[':
                end = index + 2
                while end < size and text[end] in '0123456789;?':
                    end += 1
                if end < size and ('a' <= text[end] <= 'z' or 'A' <= text[end] <= 'Z'):
                    index = end + 1
                else:
                    # Keep the legacy printable portion of an unsupported CSI,
                    # consuming its parameter run once even when no final exists.
                    shown.append(text[index + 1:end])
                    index = end
                continue
            if kind in '=><NOM78c':
                index += 2
                continue
        if char in ('\n', '\t'):
            shown.append(' ')
        elif ord(char) >= 32 and not 127 <= ord(char) <= 159:
            shown.append(char)
        index += 1
    text = ''.join(shown)
    if max_len is not None and len(text) > max_len:
        text = text[:max_len - 3] + '...'
    return text


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
