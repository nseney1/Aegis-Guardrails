---
id: trap-guard-without-mutation-test
domain: testing
type: trap
enforcement: advisory
hypothesis: "A guard whose removal leaves every test green is untested, whatever its tests assert."
prediction: A test that turns red when the guard is deleted or disabled proves the guard is exercised.
falsification: Retire if ten new guards each have a test shown to fail with the guard removed.
expiry_sessions: 15
expiry_days: 60
created: "2026-11-24T12:23:51Z"
impact_weight: 1.0
tags:
  - test_creation
  - verification_modification
target_paths:
  - "tests/**"
lineage:
  parent_id: null
  created_by: manual
  generation: 0
  siblings: []
---
## Do

Give every new guard, refusal or check a test that fails when the guard is removed; confirm it by disabling the guard once and seeing the test turn red.

A test that turns red when the guard is deleted or disabled proves the guard is exercised.

Assert the observable refusal (exit status, message, absent effect), not that a helper was called.

## Evidence

- 2026-11-24 — A review mutated two new guards to 'if False:' and the suite stayed green; both needed added tests in the next round.

Catalog comparison: extends trap-tautological-test to guards that no test exercises.
