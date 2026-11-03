---
id: trap-pytest-exit-code
domain: correctness
type: trap
enforcement: advisory
hypothesis: "Pytest exit code 5 (no tests collected) is currently penalizing valid scenarios where tests shouldn't run."
prediction: Handling exit code 5 gracefully will improve outcome engine reliability.
falsification: A lack of collected tests is always a critical failure.
target_paths:
  - "tests/*.py"
  - "aegis_core/*.py"
expiry_sessions: 30
impact_weight: 0.7
minimum_mode: patrol
tags:
  - pytest
  - exit-code
  - testing
created: 2026-09-28
---
## Do
Treat zero collected/passing tests as missing test evidence, preserve actual execution errors and timeouts, and never manufacture a passing receipt from exit status alone.

A configured command may be unavailable or collect nothing without proving a code defect. Preserve the public status/reason and deterministic check results; no-test output cannot earn witnessed test credit or be converted into a false-positive rule outcome.

Verify: Cover pytest exit 5, missing interpreters/frameworks, skipped-only/zero-test runs, malformed/missing JUnit, timeout and genuine failures through public check/test execution.

Owner instructions and existing approval/release boundaries remain authoritative.

## Evidence
- aegis_core/testexec.py: TestsRun.evidence requires exit zero, no timeout and at least one passed test.
- tests/unit/core/test_testexec.py and tests/unit/cli/test_check_record_cli.py cover execution/evidence status.
