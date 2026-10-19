"""Secret redaction utilities for command logging."""
from __future__ import annotations

from typing import Any  # noqa: F401  (pinned 4.3.3 public name, tests/contract/public_names_4_3_3.json)

from aegis_core.verification.scanners import SECRET_REPLACEMENTS, redact_command_secrets

__all__ = [
    "SECRET_REPLACEMENTS",
    "_REDACTION_PATTERNS",
    "redact_secrets",
    "redact_text",
]

_REDACTION_PATTERNS = SECRET_REPLACEMENTS


def redact_secrets(cmd: str) -> str:
    """Mask known secret patterns before logging."""
    return redact_command_secrets(cmd)


redact_text = redact_secrets
