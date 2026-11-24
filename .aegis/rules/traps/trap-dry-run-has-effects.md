---
id: trap-dry-run-has-effects
domain: correctness
type: trap
enforcement: advisory
hypothesis: "A preview, dry-run or plan mode that is ignored or only partly honoured performs the real action while the operator believes nothing changed."
prediction: Rejecting unsupported preview flags before any effect and asserting unchanged state in tests keeps previews effect-free.
falsification: Retire if ten commands with a preview mode each leave observable state unchanged in tests and reject unsupported preview flags.
expiry_sessions: 15
expiry_days: 60
created: "2026-11-24T13:16:37Z"
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

Make a preview, dry run or plan mode provably effect-free: it starts no job or process, takes no lease or lock that outlives it, and writes no record, receipt or file outside its own temporary space.

Reject a preview flag the command does not support before any effect; never ignore it and run for real.

Test each preview by asserting that the observable state is byte-identical before and after, and that the real run then produces the planned actions.

## Evidence

- 2026-11-24 — A launch helper accepted a dry-run switch it did not implement and started a real remote qualification run.
- 2026-11-24 — A release command run a second time to read its output changed fifteen queue items again.

Catalog comparison: nearest is invariant-safety-gate, which gates destructive actions but does not require previews to be effect-free.
