---
id: trap-unreadable-readback-treated-as-verdict
domain: correctness
type: trap
enforcement: advisory
hypothesis: A confirmation step that treats an empty or failed read-back as a mismatch or as a match reports a verdict it has not observed.
prediction: Verifying the returned object with a bounded retry and a distinct unknown outcome removes false mismatches without admitting wrong results.
falsification: Retire if in fifty confirmations after a state change no read-back is ever empty or failed.
expiry_sessions: 15
expiry_days: 60
created: "2026-11-24T19:07:54Z"
impact_weight: 1.0
tags:
  - reliability
  - verification
target_paths:
  - "aegis_core/**"
  - "tools/**"
lineage:
  parent_id: null
  created_by: manual
  generation: 0
  siblings: []
---
## Do

When a step changes shared state and then reads it back to confirm, treat an empty, missing or failed read as "unknown", never as a mismatch and never as a match. Verify the specific object the change returned (for example the commit or record identifier), retry the read a bounded number of times within a stated deadline, and report "unknown" if it still cannot be read.

Only a reading that was obtained and differs from the expectation is a mismatch. Only a reading that was obtained and equals it is a match.

## Evidence

- 2026-11-24 — A merge verification step read the branch tip immediately after a correct merge, got an empty answer, and reported that the result did not match the plan. Five of 84 batches ended this way; in each the merge had both expected parents and the exact tested tree, and the remaining work was requalified from the start.

Catalog comparison: nearest are trap-empty-gate-input-passes (empty input treated as a pass) and trap-fail-open-verification; neither covers an empty read-back treated as a failed verdict.
