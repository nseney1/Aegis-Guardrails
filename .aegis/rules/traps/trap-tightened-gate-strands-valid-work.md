---
id: trap-tightened-gate-strands-valid-work
domain: governance
type: trap
enforcement: advisory
hypothesis: A gate made stricter without enumerating the flows that pass today refuses valid work that has no way through.
prediction: "Listing current passing flows and giving each a pass, a recovery or a recorded refusal keeps valid work moving when a gate tightens."
falsification: Retire if ten gate-tightening changes each ship with a tested recovery for every newly refused flow.
expiry_sessions: 15
expiry_days: 60
created: "2026-11-24T15:12:20Z"
impact_weight: 1.0
tags:
  - governance
  - verification_modification
target_paths:
  - "aegis_core/**"
  - "aegis_cli/**"
  - "tools/**"
lineage:
  parent_id: null
  created_by: manual
  generation: 0
  siblings: []
---
## Do

Before making a gate stricter, list every flow that passes it today and decide each one: it still passes, it has a named recovery that exists in the same change, or it is refused on purpose with the decision recorded.

Disclose each newly refused flow as a behaviour change, with a concrete scenario, and test that the recovery works. A stricter gate with no way through for valid work is an outage, not a safeguard.

## Evidence

- 2026-11-24 — A change that unified a delivery gate was stricter than the paths it replaced in six places (an existing status line, a skipped review round, a disabled optional check, a waiver, lock scope, a leftover refusal record). Each would have stranded work that passed the day before; an independent review found them before installation.

Catalog comparison: nearest is trap-fail-open-verification, the opposite failure; no rule covers tightening without a path for valid work.
