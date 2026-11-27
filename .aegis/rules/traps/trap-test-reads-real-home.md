---
id: trap-test-reads-real-home
domain: testing
type: trap
enforcement: advisory
hypothesis: "A test that reads the invoking user's real home or configuration passes or fails with that machine's state."
prediction: Pointing home and configuration at a fixture directory for the test and its children makes the result the same on every machine.
falsification: Retire if ten tests that run product commands each pass with the real home replaced by one containing unknown configuration keys.
expiry_sessions: 15
expiry_days: 60
created: "2026-11-24T15:12:19Z"
impact_weight: 1.0
tags:
  - testing
  - test_creation
target_paths:
  - "tests/**"
lineage:
  parent_id: null
  created_by: manual
  generation: 0
  siblings: []
---
## Do

Give every test its own home and configuration directory. A test must not read the invoking user's real home, configuration, caches or credentials, even indirectly through a library default.

Set the home and configuration locations to a fixture directory for the whole test, including child processes, and assert on output that would reveal a leak (unexpected warnings or extra fields).

## Evidence

- 2026-11-24 — A payload test compared a tool's top-level output keys with a fixed set. On one machine the user's own configuration file had an unrecognised key, the tool added a warnings field, and the test failed there only. It passed with an isolated home.

Catalog comparison: nearest are trap-hardcoded-paths and trap-installer-clobbers-user-state, which cover product paths and installers, not tests reading the user's real configuration.
