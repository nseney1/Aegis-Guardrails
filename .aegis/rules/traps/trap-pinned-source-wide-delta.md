---
id: trap-pinned-source-wide-delta
domain: governance
type: trap
enforcement: advisory
hypothesis: "A change to an owner-pinned source that is wider than needed, or that arrives without exact bytes, cannot be approved by digest and costs an approval round."
prediction: Returning the smallest delta with its sha256 and unified diff lets the owner approve the exact bytes in one step.
falsification: Retire if ten pinned-source changes are each approved on first presentation with the submitted digest.
expiry_sessions: 15
expiry_days: 60
created: "2026-11-24T12:23:48Z"
impact_weight: 1.0
tags:
  - python_file_modification
  - commit_review
target_paths:
  - "tools/hierarchy_*.py"
lineage:
  parent_id: null
  created_by: manual
  generation: 0
  siblings: []
---
## Do

Change an owner-pinned source by the smallest delta that satisfies the ruling, and return the new sha256 with a unified diff for exact-byte approval; never edit the pin rows yourself.

Returning the smallest delta with its sha256 and unified diff lets the owner approve the exact bytes in one step.

Keep unrelated cleanups out of a pinned file. The approval names bytes, so any later byte change, including formatting, needs a new approval.

## Evidence

- 2026-11-24 — Two consecutive rounds on a pinned wake helper each changed more than the ruling required; each needed a new exact-byte approval before the lane could be queued.

Catalog comparison: extends the approval workflow rules; none requires a minimal delta with digest and diff.
