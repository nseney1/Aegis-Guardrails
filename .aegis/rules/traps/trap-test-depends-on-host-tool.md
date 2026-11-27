---
id: trap-test-depends-on-host-tool
domain: testing
type: trap
enforcement: advisory
hypothesis: "A test that relies on a tool installed on the developer's machine, by absolute path or inherited search path, fails or changes meaning on a clean machine."
prediction: Supplying the tool as a fixture and building the child environment from a fixed base gives the same result in a clean container as on a developer machine.
falsification: Retire if ten suites that pass on developer machines each pass unchanged in a clean container without the developer tools.
expiry_sessions: 15
expiry_days: 60
created: "2026-11-24T16:33:22Z"
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

Make every test supply the tools it needs. A test must not pass only because the developer's machine has a command installed at a fixed absolute path or reachable on the inherited search path.

When product code checks for a tool at an absolute path, give the test a way to point that check at a fixture (a parameter, a setting or a patched lookup), and assert that the fixture was the one used. When a test runs a child process, build its environment from a fixed base and add the fixture directory first; do not pass the caller's whole environment through.

Run the suite once in a clean container without the developer tools before calling a runtime check complete.

## Evidence

- 2026-11-24 — A suite passed on the developer machine and failed 16 tests in a clean Python 3.9 container. Fifteen failed because the code under test required a runner at a fixed absolute path and ignored the fake runner the tests had put on the search path. One failed because the test inherited the caller's environment and silently used a real command-line tool that only the developer machine had. The unchanged baseline failed the same way, so none of the failures came from the change under review.

Catalog comparison: nearest are trap-hardcoded-paths (product paths), trap-test-reads-real-home (user configuration) and trap-local-green-ci-red (general symptom); none covers a test that depends on a host-installed tool.
