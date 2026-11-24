---
id: trap-overlapping-transition
type: trap
enforcement: advisory
domain: correctness
hypothesis: "A failed coordinator invocation may have already committed, launched work or left an operation outstanding."
prediction: "Checking the journal and observed effects before intervention will distinguish completed steps from those still owed."
falsification: "Retire if ten interrupted or overlapping transitions all resume from the verified durable step without repeating an effect."
target_paths:
  - aegis_core/team_gitops.py
  - aegis_core/team_claims.py
triggers:
  - recovery
  - ownership_change
minimum_mode: patrol
expiry_sessions: 50
expiry_days: 180
created: 2026-11-23
---

## Do

Reconcile pending intent, current operator and observed effects before
resuming an interrupted operation, and stop at the first unmet prerequisite.

Checking the journal and observed effects before intervention will distinguish
completed steps from those still owed.

A timeout can occur after a side effect and before its receipt becomes
visible.

## Evidence

The atomic storage contract covers individual writes. The Git operations
journal explicitly accounts for effects that survive an interrupted request.

- 2026-11-20 — Put delivery under a short timeout. It committed locally and died before receipt or push (coordinator decision log).
- 2026-11-23 — Continued installation after a usage HOLD. Only a retrospective comparison established the originals matched (coordinator decision log).

Catalog comparison: extends contract-atomic-storage-boundaries.
