---
id: trap-status-without-receipt
type: trap
enforcement: advisory
domain: correctness
hypothesis: "A requested transition or a stale declaration can be misreported as observed completion."
prediction: "Status built from the event's own receipt will distinguish a claimed lane, a delivered head and an observed merge."
falsification: "Retire if ten mixed-state status reviews correctly distinguish every sampled delivery, merge and unobserved actor state using existing evidence."
target_paths:
  - aegis_core/team_status.py
  - aegis_core/team_workspace_events.py
triggers:
  - status_reporting
  - evidence_review
minimum_mode: patrol
expiry_sessions: 50
expiry_days: 180
created: 2026-11-23
---

## Do

Report a transition from its own recorded result and exact work identity, and
expose unknown or inferred state explicitly when only a request, declaration
or neighboring event is available.

Status built from the event's own receipt will distinguish a claimed lane, a
delivered head and an observed merge.

Retain the observation time and the object identity so a later state change
cannot rewrite the reported history.

## Evidence

team_status distinguishes lease declarations from actor liveness.
team_workspace_events handles merge as a distinct transition. A delivery
receipt cannot establish that event.

- 2026-11-13 — Conflated delivered work with merged work. The owner needed a corrected status (coordinator decision log).
- 2026-11-18 — Told the owner a rebase was hash-only. Nine changed payloads required a real rebase (coordinator decision log).

Catalog comparison: extends contract-witnessed-outcome-credit.
