---
id: contract-evidence-aggregation-fail-closed
domain: correctness
type: contract
enforcement: advisory
hypothesis: "Gates that merge receipts, reports, probes and verdicts treat missing, undated, contradictory or unreadable evidence as absent, so the remaining positive evidence yields PASS, reuse, success or a deletion recommendation."
prediction: "Adding one conflicting, undated, unreadable or malformed item to an otherwise passing input flips the result to pass/accept instead of hold/incomplete."
falsification: "Revisit if each aggregator has an adversarial-evidence matrix (missing, undated, contradictory, malformed) and 14 days of formal reviews yield fewer than 5 findings of this class."
expiry_sessions: 15
expiry_days: 60
created: "2026-11-26T02:44:57Z"
impact_weight: 1.0
tags:
  - review-audit-20261126
  - correctness
target_paths:
  - "aegis_core/team_*.py"
  - aegis_core/model_select.py
  - "aegis_cli/doctor_git*.py"
  - "tools/hierarchy_*.py"
lineage:
  parent_id: null
  created_by: manual
  generation: 0
  siblings: []
---
## Do
When a gate merges receipts, reports, probes or verdicts, treat missing, undated, contradictory or unreadable evidence as a typed HOLD or unknown, never as absent. PASS, reuse, success or a deletion needs every required input present, current and consistent.

Verify: for each required input, fixtures with it missing, stale, contradictory and unreadable all end in a non-PASS outcome.

Owner instructions and existing approval/release boundaries remain authoritative.

## Evidence
- Formal review history 2026-11-11 to 2026-11-25: about 333 blocking findings in this class across 25 lanes (keyword classification of 1,385 REQUEST CHANGES reviews; approximate).
- t-zeta, 2026-11-24, P1: unknown chronology hides newer negative evidence.
- dispatcher, 2026-11-24, P1: conflicting verdicts become a counted accept.
- codex-a, 2026-11-14, P2: unknown lease state becomes a deletion recommendation.
- strip-fix, 2026-11-17, High: contradictory helper outcomes produce PASS.
- grok-c, 2026-11-24, High: conflicting persisted readback doesn't block promotion.
- Why existing rules did not cover it: `trap-fail-open-verification` targets only `aegis_core/verification/*.py`, `redaction.py`, `verify.py`, `checkpoint.py` and `ast/**`, and its prediction is about crashes returning empty/True, not about merging conflicting evidence. `contract-witnessed-outcome-credit` targets only `credit.py`, `checkrun.py` and the telemetry handler. `team_gate.py` and `team_review.py` exist only on lane branches, not in this checkout, so the glob is intentional.
