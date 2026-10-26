"""The commands v4 removed and what to use instead (ADR 0005 D5, H1 hard cut).

A table with no imports: the CLI dispatcher prints the pointer for a removed name, and doctor
reads the removed ``aegis hook`` phases that v3 host configs still call, without importing the
dispatcher.
"""
from __future__ import annotations

from typing import Dict

__all__ = ["REMOVED_COMMANDS"]

_HOST_HOOK = "no replacement; remove it from your agent host's hook config"

# "name" or "name action" -> what to use instead. The longest match wins, so
# `aegis agent scan` gets its own pointer, and a removed action of a live
# command (`aegis hook session-close`, still called by v3 host hook configs)
# gets one too.
REMOVED_COMMANDS: Dict[str, str] = {
    "install": "use aegis init --host",
    "system": "use aegis doctor",
    "sys": "use aegis doctor",
    "system doctor": "use aegis doctor",
    "system drivers": "use aegis doctor",
    "system hook": "use aegis hook",
    "detect": "use aegis doctor",
    "languages": "use aegis doctor",
    "drivers": "use aegis doctor",
    "audit": "use aegis doctor",
    "rules": "use aegis status",
    "agent": "use aegis scan to see which rules apply; record outcomes with the MCP tool aegis_report_outcome",
    "agent scan": "use aegis scan",
    "agent record": "use aegis_report_outcome (MCP)",
    "report": (
        "aegis status shows rule trigger counts; "
        "outcomes are recorded with the MCP tool aegis_report_outcome"
    ),
    "completion": "no replacement",
    "skill": "no replacement",
    "handoff": "no replacement",
    "verify": "use aegis check",
    "checkpoint": "use aegis check",
    "rule clean": "no replacement; remove leaked global rule copies by hand",
    "hook pre-commit": "use aegis check --hook",
    "hook pre-invocation": _HOST_HOOK,
    "hook governance-monitor": _HOST_HOOK,
    "hook immune-init": _HOST_HOOK,
    "hook session-close": _HOST_HOOK,
    "hook stop": _HOST_HOOK,
    "hook post-session": _HOST_HOOK,
}
