---
id: trap-bound-before-work
domain: efficiency
type: trap
enforcement: advisory
hypothesis: "Size and count limits checked after enumeration, parsing or path materialisation let small hostile inputs force quadratic or unbounded work before the refusal fires."
prediction: "Inputs just over a limit (deep paths, many refs, repeated prefixes) consume superlinear time or memory before the expected refusal."
falsification: "Revisit if new limits are enforced before the bounded operation with complexity regression tests, and fewer than 5 findings appear in 14 days."
expiry_sessions: 15
expiry_days: 60
created: "2026-11-26T02:44:58Z"
impact_weight: 1.0
tags:
  - review-audit-20261126
  - efficiency
target_paths:
  - "aegis_core/team_*.py"
  - aegis_core/guidance_projection.py
  - aegis_core/primitives.py
  - aegis_core/redaction.py
  - "aegis_core/ast/drivers/js/*.py"
  - "tools/hierarchy_*.py"
lineage:
  parent_id: null
  created_by: manual
  generation: 0
  siblings: []
---
## Do
Check size, count and depth limits before doing the work they bound. No quadratic or exponential step runs on input a limit would have rejected.

Verify: oversized and deeply nested inputs are refused in bounded time.

Owner instructions and existing approval/release boundaries remain authoritative.

## Evidence
- Formal review history 2026-11-11 to 2026-11-25: about 139 blocking findings in this class across 25 lanes (keyword classification of 1,385 REQUEST CHANGES reviews; approximate).
- codex-a, 2026-11-15, P2: lease limits apply after unbounded work.
- rb2-fix, 2026-11-17, P2: quadratic processing before refusal.
- grok-d, 2026-11-15, High: excluded evidence still exhausts preflight limits.
- mc3-fix, 2026-11-23, High: the quote fix introduces quadratic work.
- t-delta, 2026-11-14, P2: quadratic filesystem work holds the writer lock longer.
- Why existing rules did not cover it: `persona-check-local-performance` is about ledger reuse in `scan`/`fitness`/`ledger`/`ast/session`. `contract-ast-driver-lifecycle` bounds driver transport only. No rule requires limits to be checked before the work.
