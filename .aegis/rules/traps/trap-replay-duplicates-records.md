---
id: trap-replay-duplicates-records
domain: correctness
type: trap
enforcement: advisory
hypothesis: A state-changing command that appends without an identity key writes duplicate records when it is run again.
prediction: Keying each record on what it describes makes a repeated run a no-op that reports the existing record.
falsification: Retire if ten state-changing commands each leave exactly one record after two identical runs in tests.
expiry_sessions: 15
expiry_days: 60
created: "2026-11-24T13:16:38Z"
impact_weight: 1.0
tags:
  - correctness
  - python_file_modification
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

Make every state-changing command safe to run twice: key each record it writes on the identity of the thing it describes, and treat a repeat with the same key as a no-op that reports the existing record.

Never append on replay. A timestamp is not an identity; compare records ignoring the time they were written.

Test the second run: same inputs, same exit status, one record.

## Evidence

- 2026-11-24 — A release command applied twice appended duplicate release rulings to fifteen items; the helper restamps each ruling and appends unconditionally.
- 2026-11-23 — An earlier batch of the same command crashed part-way, leaving a partial result that needed a second run.

Catalog comparison: nearest are trap-installer-clobbers-user-state (installers only) and invariant-single-canonical-ledger (one ledger); neither covers replayed commands in general.
