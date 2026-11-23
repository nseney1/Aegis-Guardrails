"""Secret redaction utilities for command logging."""
from __future__ import annotations

import re
from typing import Any  # noqa: F401  (pinned 4.3.3 public name, tests/contract/public_names_4_3_3.json)

from aegis_core.redaction import MAX_LINE_LENGTH, SECRET_REPLACEMENTS, redact_command_secrets
from aegis_core.redaction_patterns import CONTROL_RE

__all__ = [
    "SECRET_REPLACEMENTS",
    "_REDACTION_PATTERNS",
    "redact_secrets",
    "redact_text",
]

_REDACTION_PATTERNS = SECRET_REPLACEMENTS
# TAB and LF stay separators. Every other C0/C1 control selects the command head.
_COMMAND_CONTROL_RE = re.compile(CONTROL_RE.pattern + r"(?<![\t\n])")


def _command_head_end(cmd: str) -> int:
    """Analyse a command only up to its first ESC or C1 control.

    The scan stops at 4096 characters when no earlier introducer exists. Text
    after that index is not stored.
    """
    limit = min(len(cmd), MAX_LINE_LENGTH)
    for index in range(limit):
        char = cmd[index]
        if char == "\x1b" or "\x80" <= char <= "\x9f":
            return index
    return limit


def redact_secrets(cmd: str) -> str:
    """Mask known secret patterns before logging.

    A control-bearing command is cut at the first ESC or C1 control. The shared
    display detector withholds a secret tail past that head, then the hook rule
    table replaces secrets in the retained field.
    """
    # Any C0/C1 other than TAB or LF selects the head. The detector sees only that head.
    if _COMMAND_CONTROL_RE.search(cmd) is not None:
        from aegis_core.primitives import redact_display_secrets

        end = _command_head_end(cmd)
        cmd = redact_display_secrets(cmd[:end], limit=end, secret_tail=len(cmd) > end)
    return redact_command_secrets(cmd)


redact_text = redact_secrets
