---
id: trap-incomplete-qualification
type: trap
enforcement: advisory
domain: correctness
hypothesis: "A passing subset or a differently scoped receipt can conceal outstanding obligations for the same candidate."
prediction: "Reconciling the required checks with the observed pass records will retain a missing leg as pending."
falsification: "Retire if ten partial retries all leave uncovered requirements pending under the existing qualification checks."
target_paths:
  - aegis_core/team_qualify.py
triggers:
  - verification_modification
  - evidence_review
minimum_mode: patrol
expiry_sessions: 50
expiry_days: 180
created: 2026-11-23
---

## Do

Compare required qualification legs with successful observations on the
candidate tree, and preserve each missing leg when a retry covers only part of
an earlier request.

Reconciling the required checks with the observed pass records will retain a
missing leg as pending.

Associate each successful observation with the revision and requirement it
actually covers.

## Evidence

team_qualify.qualified takes required legs. Here the missing information is
the outstanding set across retries, even when every receipt presented is
genuine.

- 2026-11-19 — Requeued the same reviewed tree expecting a new decision. The existing refusal stood and the full was withdrawn (coordinator decision log).
- 2026-11-21 — Retried only seven selectors. A second plan had to cover both failed runs (coordinator decision log).

Catalog comparison: extends contract-witnessed-outcome-credit.
