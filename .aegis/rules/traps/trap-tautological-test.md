---
id: trap-tautological-test
domain: testing
type: trap
enforcement: advisory
hypothesis: "Tests that assert only types (isinstance), test at single degenerate data points where all formulas trivially agree, or call the wrong function entirely provide zero verification value while inflating test counts and creating false confidence in suite coverage"
prediction: "Will fire when a test asserts isinstance/type checks without behavioral assertions, or tests at boundary values where correct and incorrect implementations are indistinguishable"
falsification: 0 findings in 10 sessions → prune
target_paths:
  - "tests/*.py"
  - "tests/*.py"
triggers:
  - test_creation
  - test_modification
  - review_cycle
minimum_mode: sweep
expiry_sessions: 50
expiry_days: 180
created: 2026-10-01
impact_weight: 1.0
tags:
  - quality
  - testing
  - false-confidence
  - verification
---

Tests must exercise the function-under-test with inputs that DISTINGUISH
correct behavior from incorrect behavior. A test that passes regardless
of whether the implementation is right or wrong is worse than no test —
it inflates the pass count and creates false confidence.

Phase 3 incidents (test_critical_fixes.py, 4 tests):
1. `test_rule_promote_normalize_fitness_callable` — asserted only
   `isinstance(result, dict)`. Would pass for ANY function returning a dict.
2. `test_rule_fitness_agrees_with_shared_module` — tested with tp=0, fp=0
   where Jeffreys prior (0.5) and Laplace posterior (0.5) trivially agree.
   Masked a real divergence on all non-zero inputs.
3. `test_normalize_fitness_zero_triggers_not_promoted` — called
   `normalize_fitness()` instead of promotion logic. Asserted `score is
   None or score <= 0.5`, which passed vacuously because the `score` key
   was absent in the returned dict.
4. `test_normalize_fitness_high_triggers_preserves_data` — tested dict
   pass-through (`dict.get`), not actual normalization behavior.

Distinct from `trap-happy-path-only-tests`:
- Happy-path-only: tests the RIGHT thing but only for success cases
- Tautological: tests NOTHING meaningful — passes regardless of correctness

Detection heuristic: Tests whose only assertions are `isinstance()`,
`assertIsNotNone()`, or `assert X in Y` where X is a type/key check.
