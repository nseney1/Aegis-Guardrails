---
id: trap-spool-without-retention
domain: correctness
type: trap
enforcement: advisory
hypothesis: A spool or receipt store without an in-flight cap and terminal-state cleanup grows without limit and lets one requester exhaust it.
prediction: A per-requester in-flight cap and cleanup after terminal states keep the store bounded under repeated requests.
falsification: Retire if ten reviewed spools each show a per-requester cap and remove entries after terminal states.
expiry_sessions: 15
expiry_days: 60
created: "2026-11-24T12:23:50Z"
impact_weight: 1.0
tags:
  - feature_addition
  - python_file_modification
target_paths:
  - tools/hierarchy_jobs.py
  - aegis_core/team_queue.py
lineage:
  parent_id: null
  created_by: manual
  generation: 0
  siblings: []
---
## Do

Give every spool and receipt store retention: cap the in-flight entries per requester and clean up entries after they reach a terminal state.

A per-requester in-flight cap and cleanup after terminal states keep the store bounded under repeated requests.

State the cap and the retention period next to the store, and test that the entry after the cap is refused and that a terminal entry is removed.

## Evidence

- 2026-11-24 — Review of a request spool found no per-requester limit and no cleanup after terminal states.

Catalog comparison: no existing rule requires retention for spools and receipts.
