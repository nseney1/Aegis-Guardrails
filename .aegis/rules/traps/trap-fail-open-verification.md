---
id: trap-fail-open-verification
domain: security
type: trap
enforcement: advisory
hypothesis: "Verification tools that return empty/success on execution failure silently bypass the safety gate — the tool reports \"all checks passed\" when it actually crashed before checking anything"
prediction: "Will fire when a verification function returns an empty list, True, or exit code 0 on an error path (missing file, crashed subprocess, None data)"
falsification: 0 findings in 10 sessions → prune
target_paths:
  - "aegis_core/verification/*.py"
  - aegis_core/redaction.py
  - aegis_cli/verify.py
  - aegis_cli/checkpoint.py
  - "aegis_core/ast/**"
triggers:
  - verification_modification
  - error_handling_change
  - security_review
minimum_mode: patrol
expiry_sessions: 50
expiry_days: 180
created: 2026-09-30
impact_weight: 1.0
tags:
  - security
  - verification
  - fail-open
  - critical
---

Verification tools MUST fail-closed: any execution error must produce a
FAIL verdict, never a PASS.

Citadel Cycle 2 incidents:
1. `branch_coverage.py:137` — when trace script crashed, `results_file` didn't
   exist, function returned `[]`, caller computed `verdict = len([]) == 0` → True
   (all branches covered). Fix: return `None` on crash, caller treats as fail.

2. `branch_coverage.py:210` — when target file wasn't in coverage report,
   `file_data is None` returned `[]` → verdict True. An untested file passed
   coverage. Fix: return `[-1]` sentinel so verdict is False.

3. `verify.py:128` — when all --files were out-of-tree, `safe_files` became `[]`,
   verification ran on nothing, exited 0 (PASS). Fix: exit 1 when explicit
   files are provided but none are in-tree.

4. v4 Citadel review, `forbid_ast` (fixed in wave A1):
   `extract_normalized_ast` returned None on any exception (a RecursionError on
   a deeply nested expression, say) and the runner did `continue`, so a
   forbid_ast gate rule silently passed. Alias forms evaded call bans
   (`import os as o`, `from os import system as s`, `getattr`, `__import__`,
   `importlib`, `e = eval`). It was missed because the tests counted positive
   hits through private helpers with no negative controls, and the code had been
   moved verbatim, so its gaps were waved off as pre-existing.

Deterministic policy checks follow the same rule: when a file a rule applies
to cannot be analyzed, emit a failing result instead of skipping the file;
resolve aliases through the real imported name; parse each file at most once
per scan, behind a cheap text prefilter.

Detection: grep for `return []` in verification functions and check if the
caller treats empty as success. In `aegis_core/ast/`, every `continue` or
`return None` after a failed parse must yield a failing result; test with an
unparseable file and with each alias form, and assert a violation.
