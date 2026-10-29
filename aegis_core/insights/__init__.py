"""Human insights closed loop (v4.3 spec §3.5 T8, v4.4 spec §3.4 & §12.2).

Four modules, each importing only the ones listed before it: ``keys`` (the link key, session
hashes, the workspace id, row I/O), ``capture`` (correction cues, the hook prompt recorder,
CLI and agent insights, the host hook entry), ``review`` (rule matching, neighbours,
decisions, proposals) and ``recurrence``. This package re-exports their public names.

The per-prompt hook path (record_hook_prompt) imports only the standard library and the
L0 modules at module load, the redaction table among them: credit, human_gate, the ledger,
scan_compliance and the rule parser are imported where review or capture uses them, so a
prompt that writes nothing pays for none of them.

Rows of the user-scope log (compact JSONL, appended under a lock, never rewritten):
``heartbeat`` {host, hs, cue, inv} on every hook prompt that carries a session id, text
free, where ``inv`` is the first 16 hex of the rule-bytes fingerprint (absent without rule
files); ``inventory`` {inv, revs} once per first-seen ``inv``, the only place the hook
parses rules; ``insight`` and ``decision``. A prompt with no session id and no excerpt
writes nothing. Old heartbeats that carry their own ``revs`` stay readable.
"""
from __future__ import annotations

from aegis_core.insights.capture import (
    INSIGHT_HOOK_MARKER,
    JOIN_WINDOW_S,
    MAX_CAPTURE_PATH_CHARS as MAX_CAPTURE_PATH_CHARS,
    MAX_CAPTURE_PATHS as MAX_CAPTURE_PATHS,
    MAX_CAPTURES_PER_SESSION,
    CaptureLimitReached,
    add_insight,
    capture_suggestion,
    dirty_paths,
    effective_capture,
    has_correction_cue,
    host_capture_status,
    merge_insight_hook,
    record_hook_prompt,
    remove_insight_hook,
)
from aegis_core.insights.keys import (
    COUNTABLE_LEVELS as COUNTABLE_LEVELS,
    INSIGHT_SCHEMA_VERSION as INSIGHT_SCHEMA_VERSION,
    KEY_SIZE,
    SUPPORTED_INSIGHT_HOSTS,
    create_link_key,
    insight_workspace_id,
    insights_path,
    read_insight_rows,
    read_link_key,
    session_hs,
)
from aegis_core.insights.recurrence import (
    BURST_WINDOW_SECONDS as BURST_WINDOW_SECONDS,
    RECURRENCE_ALARM_COUNT as RECURRENCE_ALARM_COUNT,
    RECURRENCE_DENOMINATOR,
    RECURRENCE_SIM,
    insight_born_rules,
    insight_status,
    insight_status_lines,
    measure_recurrence,
)
from aegis_core.insights.review import (
    DECISIONS as DECISIONS,
    REJECTION_RESURFACE_COUNT as REJECTION_RESURFACE_COUNT,
    RULE_MATCH_SIM,
    RULE_MATCH_SIM_WITH_PATH,
    record_decision,
    review_insights,
    write_proposal,
)
from aegis_core.redaction import redact_insight_text

# The ``X as X`` names above are the public constants insights.py defined outside __all__: still
# importable from the package, still outside __all__.
__all__ = [
    "CaptureLimitReached",
    "INSIGHT_HOOK_MARKER",
    "JOIN_WINDOW_S",
    "KEY_SIZE",
    "MAX_CAPTURES_PER_SESSION",
    "RECURRENCE_DENOMINATOR",
    "RECURRENCE_SIM",
    "RULE_MATCH_SIM",
    "RULE_MATCH_SIM_WITH_PATH",
    "SUPPORTED_INSIGHT_HOSTS",
    "add_insight",
    "capture_suggestion",
    "create_link_key",
    "dirty_paths",
    "effective_capture",
    "has_correction_cue",
    "host_capture_status",
    "insight_born_rules",
    "insight_status",
    "insight_status_lines",
    "insight_workspace_id",
    "insights_path",
    "measure_recurrence",
    "merge_insight_hook",
    "read_insight_rows",
    "read_link_key",
    "record_decision",
    "record_hook_prompt",
    "redact_insight_text",
    "remove_insight_hook",
    "review_insights",
    "session_hs",
    "write_proposal",
]
