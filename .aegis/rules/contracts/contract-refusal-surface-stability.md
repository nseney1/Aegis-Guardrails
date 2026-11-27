---
id: contract-refusal-surface-stability
domain: correctness
type: contract
enforcement: advisory
hypothesis: "Fixes that reorder preflight checks, truncate output or change decoding alter refusal codes, exit status, advice and legacy bytes that callers depend on, and the delivery's tests encode the new behaviour instead of the base commit's."
prediction: "A diff touching a refusal path without a base-vs-candidate refusal golden draws a 'differs from baseline / changes legacy refusal' finding."
falsification: Revisit if refusal goldens are generated from the base commit for every changed refusal path and fewer than 5 such findings appear in 14 days.
expiry_sessions: 15
expiry_days: 60
created: "2026-11-26T02:44:58Z"
impact_weight: 1.0
tags:
  - review-audit-20261126
  - correctness
target_paths:
  - "tools/hierarchy_*.py"
  - "aegis_cli/*.py"
  - "aegis_core/team_*.py"
  - aegis_mcp/server.py
  - "tests/unit/cli/*.py"
lineage:
  parent_id: null
  created_by: manual
  generation: 0
  siblings: []
---
## Do
A fix keeps existing refusal codes, exit statuses, recovery advice and caller behaviour unless changing them is the stated purpose of the item. Any change to that surface is deliberate, documented and tested against the legacy callers.

Verify: contract tests pin the refusal codes and advice, and compatibility tests run the existing callers.

Owner instructions and existing approval/release boundaries remain authoritative.

## Evidence
- Formal review history 2026-11-11 to 2026-11-25: about 225 blocking findings in this class across 24 lanes (keyword classification of 1,385 REQUEST CHANGES reviews; approximate).
- pr6, 2026-11-13, P2: no-plan CLI refusals differ from the baseline.
- grok-b, 2026-11-14, P2: new preflight ordering changes refusal codes.
- mc3-split, 2026-11-14, P2: blanket truncation changes existing refusal output.
- codex-a, 2026-11-22, Medium: MCP pre-dispatch traceback bytes changed.
- strip-fix, 2026-11-12, P2: disabled records change legacy refusals.
- t-theta, 2026-11-24, Medium: non-usage refusals fire before usage validation.
- Why existing rules did not cover it: `contract-mcp-cli-parity` is about drift between the CLI, MCP and SDK adapters (registry/schema files). `invariant-decomposition-merge-gate` pins public names during code moves. Neither requires base-commit refusal goldens for ordinary fixes, and neither reaches `tools/**`.
