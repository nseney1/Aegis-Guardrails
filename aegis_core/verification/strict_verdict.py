"""The blocking predicate shared by Layer 1 gates and report projections."""
from __future__ import annotations

from .ast_checks import NO_DRIVER_NOTE_TOOL


def evidence_blocks(verdict: bool, tool: str, *, strict: bool = False) -> bool:
    """A failed tool blocks; strict mode also blocks a missing-driver coverage note."""
    return not verdict or (strict and tool == NO_DRIVER_NOTE_TOOL)
