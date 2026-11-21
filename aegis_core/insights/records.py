"""Closed insight field policy and the one decision enumeration.

Capture and review import these names. Neither module keeps a second copy.
"""
from __future__ import annotations

__all__ = [
    "DECISIONS",
    "INSIGHT_FIELD_POLICIES",
    "MAX_INSIGHT_ITEMS",
]

MAX_INSIGHT_ITEMS = 4096

DECISIONS = ("propose", "reject", "snooze", "merge-into-rule", "noise", "confirm")

# Every persisted field has one policy. Unknown fields refuse before append.
INSIGHT_FIELD_POLICIES = {
    "v": "identity", "ts": "identity", "event": "identity", "id": "identity",
    "level": "identity", "text": "text", "paths": "path", "psrc": "identity",
    "host": "text", "hs": "identity", "source": "identity", "kind": "text",
    "approval_code": "identity", "revs": "identity", "corroborated_by": "identity",
    "paths_dropped": "identity", "cue": "identity", "inv": "identity",
    "decision": "identity", "insight_ids": "identity", "reason": "text", "rule_id": "identity",
}
