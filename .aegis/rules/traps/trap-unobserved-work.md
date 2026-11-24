---
id: trap-unobserved-work
type: trap
enforcement: advisory
domain: efficiency
hypothesis: "A status feed can suppress a claim or omit a terminal job while the coordinator still expects progress."
prediction: "An expected transition without a matching observation will surface as outstanding at the next status check."
falsification: "Retire if ten checkpoints with a suppressed claim or a silent terminal result all identify the due action without this reminder."
target_paths:
  - aegis_core/team_queue.py
  - aegis_core/team_supervisor_observe.py
triggers:
  - status_reporting
  - queue_change
minimum_mode: patrol
expiry_sessions: 50
expiry_days: 180
created: 2026-11-23
---

## Do

Reconcile expected starts and terminal outcomes with current queue and
supervisor observations, and surface each overdue transition with its work
identity and next action.

An expected transition without a matching observation will surface as
outstanding at the next status check.

Include outstanding work even when no event arrived during the current
polling interval.

## Evidence

Queue claim state and supervisor observations provide two views for a status
consumer. An expired declaration by itself cannot prove that a worker stopped.

- 2026-11-19 — Missed the terminal HOLD across a resume. The combined install window waited about 18 hours (coordinator decision log).
- 2026-11-19 — Missed the TA-2b follow-up. The scan attributed about 43.2 hours to it (coordinator decision log).

Catalog comparison: new.
