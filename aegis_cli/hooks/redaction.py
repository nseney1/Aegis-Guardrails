"""Secret redaction utilities for command logging."""
from __future__ import annotations

from typing import Any

from aegis_core.verification.scanners import (
    HOOK_REDACTION_PATTERNS,
    SECRET_REPLACEMENTS,
    redact_command_secrets,
    redact_payload as _scanner_redact_payload,
)

__all__ = [
    "HOOK_REDACTION_PATTERNS",
    "SECRET_REPLACEMENTS",
    "_REDACTION_PATTERNS",
    "redact_payload",
    "redact_secrets",
    "redact_text",
]

_REDACTION_PATTERNS = SECRET_REPLACEMENTS


def redact_secrets(cmd: str) -> str:
    """Mask known secret patterns before logging."""
    return redact_command_secrets(cmd)


redact_text = redact_secrets


def redact_payload(payload: Any) -> Any:
    """Recursively mask known secret patterns in a hook payload."""
    return _scanner_redact_payload(payload)
