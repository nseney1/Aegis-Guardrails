---
id: trap-retry-budget
type: trap
enforcement: advisory
domain: efficiency
hypothesis: "A retry with the same effective window can repeatedly exhaust capacity while appearing to wait for a slot."
prediction: "Reporting the exhausted budget with the failed attempt will distinguish an infeasible retry from a genuine capacity wait."
falsification: "Retire if ten deadline-limited retries each identify the limiting window and obtain a feasible execution plan before admission."
target_paths:
  - tools/hierarchy_jobs.py
triggers:
  - resource_budget
  - retry
minimum_mode: patrol
expiry_sessions: 50
expiry_days: 180
created: 2026-11-23
---

## Do

Compare the failed attempt’s runtime and remaining work with the effective
reservation and deadline before scheduling another attempt, and preserve the
limiting reason in the receipt.

Reporting the exhausted budget with the failed attempt will distinguish an
infeasible retry from a genuine capacity wait.

Account for time reserved for other stages and for competing work in the
same reservation.

## Evidence

The jobs runner admits work against recipes, heavy reservations and execution
budgets. The product lesson is distinguishing budget exhaustion from
contention. The VM planner and its local timeout constants stay in the kit.

- 2026-11-18 — Relaunched without consulting runtime history. The coordinator withdrew the new run and parked the lane (coordinator decision log).
- 2026-11-21 — Kept retrying a serial selection longer than its deadline. Seven timeouts cost about 11.7 slot-hours (coordinator decision log).

Catalog comparison: new.
