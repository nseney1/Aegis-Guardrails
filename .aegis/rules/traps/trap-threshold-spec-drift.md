---
id: trap-threshold-spec-drift
domain: correctness
type: trap
enforcement: advisory
hypothesis: "When numeric thresholds are documented in docstrings with > but implemented with >= (or vice versa), boundary behavior silently diverges from the specification"
prediction: "Will catch threshold comparisons where the operator doesn't match the documented behavior"
falsification: 0 findings in 20 sessions → prune
target_paths:
  - "aegis_core/*.py"
  - "aegis_cli/*.py"
triggers:
  - threshold_modification
  - docstring_update
  - correctness_review
minimum_mode: patrol
expiry_sessions: 30
expiry_days: 90
created: 2026-09-30
impact_weight: 1.0
tags:
  - correctness
  - specification
  - boundary
---

Citadel C3 incident: `lifecycle.py` docstring said `tp_rate > 0.85` and
`age > 30 days` but code used `<` operator which permits equality (>= semantics).
Also: demotion had no minimum sample size (1 trigger with 1 FP = immediate
demotion) and dormancy check was unreachable.
