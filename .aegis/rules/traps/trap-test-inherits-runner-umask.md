---
id: trap-test-inherits-runner-umask
domain: testing
type: trap
enforcement: advisory
hypothesis: A test that creates files or custody state under the inherited umask passes or fails with the runner environment.
prediction: Setting the umask and modes inside the test gives the same result under any runner umask.
falsification: "Retire if ten file-creating tests each pass under umask 002, 022 and 077."
expiry_sessions: 15
expiry_days: 60
created: "2026-11-24T12:23:53Z"
impact_weight: 1.0
tags:
  - test_creation
  - test_fix
target_paths:
  - "tests/**"
lineage:
  parent_id: null
  created_by: manual
  generation: 0
  siblings: []
---
## Do

Tests that create files or custody state set their own umask and modes and never inherit the runner's.

Setting the umask and modes inside the test gives the same result under any runner umask.

Restore the previous umask in teardown. A custody check that refuses a group-writable directory is working; the fixture must create the directory with the mode the check expects.

## Evidence

- 2026-11-12 — Under umask 002 the fixture directories of one suite became group-writable and custody refused them: 56 of 134 tests failed and two earlier reruns were invalid.

Catalog comparison: nearest is contract-atomic-storage-boundaries, which covers product writes under umasks, not test fixtures.
