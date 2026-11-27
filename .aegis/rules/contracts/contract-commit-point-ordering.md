---
id: contract-commit-point-ordering
domain: correctness
type: contract
enforcement: advisory
hypothesis: "Operations that publish, deliver or acknowledge before all eligibility checks and durability complete, or that validate outside the lock guarding the commit, leave side effects on refusal or accept concurrent rewrites."
prediction: "Injecting a refusal, an fsync failure or a concurrent writer between check and commit leaves a published file, sent message or acknowledgement with no matching commit or hold."
falsification: "Revisit if every publish path has fault-injection tests (refusal after first effect, fsync failure, concurrent writer) and fewer than 5 findings appear in 14 days."
expiry_sessions: 15
expiry_days: 60
created: "2026-11-26T02:44:58Z"
impact_weight: 1.0
tags:
  - review-audit-20261126
  - correctness
target_paths:
  - "aegis_core/team_mailbox*.py"
  - aegis_core/proposals/store.py
  - aegis_core/merge_queue.py
  - aegis_core/team_claims.py
  - tools/hierarchy_small_change_dispatch.py
  - tools/hierarchy_fresh_brief.py
  - tools/hierarchy_mailbox_records.py
lineage:
  parent_id: null
  created_by: manual
  generation: 0
  siblings: []
---
## Do
Repeat every admission check under the same lock that commits the change, and perform outward side effects (publish, send, acknowledge) only after validation and a durable commit.

Verify: a fixture changes state between the check and the commit and is refused; ordering assertions show no side effect before the commit.

Owner instructions and existing approval/release boundaries remain authoritative.

## Evidence
- Formal review history 2026-11-11 to 2026-11-25: about 158 blocking findings in this class across 25 lanes (keyword classification of 1,385 REQUEST CHANGES reviews; approximate).
- census-5b, 2026-11-20, P2: HOLD eligibility is checked after mailbox delivery.
- grok-c, 2026-11-16, P2: a draft can refuse after publishing evidence.
- t-epsilon, 2026-11-13, P2: event head reaches Git before validation.
- mc3-split, 2026-11-17, P2: cursor completion precedes durable notice publication.
- codex-d, 2026-11-14, Medium: retries acknowledge unflushed publications.
- t-gamma, 2026-11-14, High: final snapshot reread accepts concurrent rewrites.
- Why existing rules did not cover it: `invariant-single-canonical-ledger` covers locked read-modify-write only for the telemetry ledger. `contract-atomic-storage-boundaries` covers the storage primitives. No rule addresses where validation sits relative to publication in the team or hierarchy flows.
