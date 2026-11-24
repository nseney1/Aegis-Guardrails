---
id: trap-empty-gate-input-passes
domain: security
type: trap
enforcement: advisory
hypothesis: "A launcher or verdict parser that accepts empty, truncated or unparseable input reports success for work that never ran."
prediction: Treating such input as an error stops the run or the verdict before a pass is recorded.
falsification: "Retire if ten gate inputs and verdict parsers each reject empty, truncated and unparseable input in tests."
expiry_sessions: 15
expiry_days: 60
created: "2026-11-24T12:23:52Z"
impact_weight: 1.0
tags:
  - security_review
  - verification_modification
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

Make gate inputs and verdicts fail closed: a launcher or verdict parser treats an empty input, a cut-off result or unparseable text as an error, never as a pass.

Treating such input as an error stops the run or the verdict before a pass is recorded.

Check size and completeness before launch, and require an explicit terminal status before reading a score. A placeholder result is not a verdict.

## Evidence

- 2026-11-13 — Two review jobs ran to exit 0 on an empty brief.
- 2026-11-24 — Twenty-six review runs that ended in an error status still produced a confirmed-findings score from partial text.
- 2026-11-23 — A placeholder line from a failed fallback was read as a verdict and stopped a full run.

Catalog comparison: nearest is contract-ast-driver-lifecycle, which covers truncated AST-driver output only.
