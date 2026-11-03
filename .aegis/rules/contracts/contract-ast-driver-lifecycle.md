---
id: contract-ast-driver-lifecycle
type: contract
domain: security
enforcement: advisory
hypothesis: "A reusable driver session is safe only while transport bounds and process ownership remain intact."
prediction: "Malformed or hung drivers can leak processes, mix responses, or make unavailable analysis look successful."
falsification: "Revisit when a reviewed public contract replaces the stated behavior or the cited regression no longer tests its failure."
minimum_mode: patrol
tags: [project-contract, v4.5]
target_paths:
  - "aegis_core/ast/batch.py"
  - "aegis_core/ast/runner.py"
  - "aegis_core/ast/gobuild.py"
  - "aegis_core/ast/windows_job.py"
  - "tests/unit/core/test_ast_batch_m1.py"
---
## Do
Run only trusted AST driver plans with bounded requests, responses, diagnostics and deadlines; correlate each response, poison broken sessions and clean up owned processes on every exit path.

Keep executable selection outside repository authority, isolate child state and preserve first-party/user configuration boundaries. Enforce absolute executable resolution and platform-specific process cleanup. Lazy driver preparation must not be triggered by read-only descriptions.

Verify: Exercise missing executables, malformed handshakes/IDs, oversized/truncated output, EOF, timeout, repeated calls after failure and Windows/POSIX ownership cleanup.

Owner instructions and existing approval/release boundaries remain authoritative.

## Evidence
- aegis_core/ast/batch.py documents a sequential bounded NDJSON process that is permanently poisoned on protocol defects.
- aegis_core/ast/runner.py separates unavailable plans, registered drivers, packaged templates and user-scope configuration.
- tests/unit/core/test_ast_batch_m1.py, test_ast_driver_runner.py and test_ast_windows_job.py cover transport/process boundaries.
