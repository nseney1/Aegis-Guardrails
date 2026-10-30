---
id: trap-bugfix-without-regression-test
domain: testing
type: trap
enforcement: advisory
hypothesis: "Bug fixes applied without corresponding regression tests will allow the same defect to recur, compounding fix-refix cycles"
prediction: Will fire when a commit fixes a bug (changes implementation code) but does not add or modify a test that exercises the fixed behavior
falsification: 0 findings in 20 sessions → prune
target_paths:
  - "aegis_core/*.py"
  - "aegis_sdk/*.py"
  - "aegis_cli/*.py"
  - "aegis_mcp/*.py"
triggers:
  - bug_fix
  - commit_review
  - code_modification
minimum_mode: patrol
expiry_sessions: 30
expiry_days: 90
created: 2026-10-01
impact_weight: 1.2
tags:
  - testing
  - regression
  - quality
  - process
---

v0.81 origin: Bugs 1-3 in telemetry.py and sync.py were fixed without
regression tests. The telemetry path (.aegis/outcomes.jsonl → .aegis/evidence/outcomes.jsonl),
schema key (rules_used → rule_id), and outcome mapping (success→tp, failure→fp) were
all corrected surgically but had zero test coverage for the fixed behavior. This rule
ensures every bug fix is paired with a test proving the fix works and guarding against
regression.
