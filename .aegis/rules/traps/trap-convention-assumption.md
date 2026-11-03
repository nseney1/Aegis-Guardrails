---
id: trap-convention-assumption
domain: correctness
type: trap
enforcement: advisory
hypothesis: Assuming a schema field value or naming convention without verifying against existing instances causes silent contract violations that pass new tests but fail regression
prediction: "Will fire when new files are created with field values that don't match existing files of the same type"
falsification: 0 findings in 10 sessions → prune
target_paths:
  - ".aegis/rules/*.md"
  - "**/*.py"
triggers:
  - rule_creation
  - schema_definition
  - convention_review
minimum_mode: patrol
expiry_sessions: 30
expiry_days: 90
created: 2026-09-30
impact_weight: 1.0
tags:
  - correctness
  - convention
  - dogfooding
---

Before creating new instances of a typed artifact (rules, config files, schema
records), ALWAYS read at least one existing instance of the same type to ground
the field values and naming conventions.

Citadel enforcement incident: 5 invariant rules were created with `enforcement: blocking`
instead of `enforcement: gate`. The agent assumed the value, wrote new tests that
codified the wrong value (circular self-consistency), and only the pre-existing
rule-metadata test (now `tests/unit/core/test_rule_lint.py`) caught the mismatch. A 3-second `grep "enforcement"
.aegis/rules/invariants/*.md` would have prevented the error.

Detection: When creating N>1 instances of a type, grep existing instances first.
If the new instance's field values don't match, halt and verify.
