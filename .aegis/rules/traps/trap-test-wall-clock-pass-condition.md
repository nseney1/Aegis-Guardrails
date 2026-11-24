---
id: trap-test-wall-clock-pass-condition
domain: testing
type: trap
enforcement: advisory
hypothesis: A test whose pass condition includes a fixed wall-clock timeout fails under load although the code is correct.
prediction: Bounding the work instead of the clock and reporting hangs separately keeps the result independent of machine speed.
falsification: Retire if ten new concurrency tests each pass twenty consecutive runs under the full parallel suite.
expiry_sessions: 15
expiry_days: 60
created: "2026-11-24T15:12:19Z"
impact_weight: 1.0
tags:
  - testing
  - test_creation
target_paths:
  - "tests/**"
lineage:
  parent_id: null
  created_by: manual
  generation: 0
  siblings: []
---
## Do

Never let elapsed wall-clock time decide whether a test passes. Bound the work (iterations, bytes, events), not the clock; wait for completion rather than for a number of seconds.

Where a hang guard is needed, make it generous and report a hang distinctly from an assertion failure, so a slow machine cannot turn into a red result.

Run a new concurrency test once under the full parallel suite before calling it done.

## Evidence

- 2026-11-24 — A new test waited at most 30 seconds on a background task. It passed in targeted runs and failed the full parallel suite under load before any assertion ran, costing a full qualification run.

Catalog comparison: nearest is trap-local-green-ci-red, which is about reading the failing log, not about time-dependent pass conditions.
