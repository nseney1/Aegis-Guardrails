---
id: contract-anchored-path-identity
domain: security
type: contract
enforcement: advisory
hypothesis: "Path-based check-then-use sequences (lstat then open, gitfile read then directory watch, normalise then walk) let a writer swap a component between reads, so validation certifies a different object from the one used."
prediction: "Replacing a parent, ancestor or gitdir between two reads in a test produces acceptance instead of refusal."
falsification: "Revisit if model-writable trees are touched only through descriptor-anchored helpers with identity comparison and swap-injection tests, and fewer than 5 findings appear in 14 days."
expiry_sessions: 15
expiry_days: 60
created: "2026-11-26T02:44:57Z"
impact_weight: 1.0
tags:
  - review-audit-20261126
  - security
target_paths:
  - "tools/hierarchy_*.py"
  - "aegis_core/workspace/*.py"
  - aegis_core/storage_confined.py
  - "aegis_core/team_mailbox*.py"
  - aegis_core/gitops_fds.py
  - aegis_core/pathlookup.py
  - tests/integration/test_hierarchy_provider_recovery.py
lineage:
  parent_id: null
  created_by: manual
  generation: 0
  siblings: []
---
## Do
Bind each check to the object it authorises. Open relative to a verified directory descriptor with no-follow semantics, validate with fstat on the opened descriptor, and re-verify device and inode after any re-resolution. Never validate a path string and then reopen it by name.

Verify: tests that swap a symlink, an ancestor directory or a gitdir between the check and the use are refused.

Owner instructions and existing approval/release boundaries remain authoritative.

## Evidence
- Formal review history 2026-11-11 to 2026-11-25: about 242 blocking findings in this class across 25 lanes (keyword classification of 1,385 REQUEST CHANGES reviews; approximate).
- codex-a, 2026-11-23, High: admin directory replaced between reads is accepted.
- census-5b, 2026-11-19, P1: successful `mkdir` certifies a substituted directory.
- codex-b, 2026-11-20, High: export publishes an out-of-tree absolute symlink.
- strip-fix, 2026-11-13, P1: executable symlinks bypass the effect fence.
- codex-d, 2026-11-19, P1: shadow I/O bypasses the owner-private path guard.
- Why existing rules did not cover it: `contract-atomic-storage-boundaries` has the right semantics but its scope is `storage.py`, `storage_shared.py`, `atomicio.py` and their tests. `trap-path-traversal` is about lexical containment of user-supplied paths, not swaps between check and use.
