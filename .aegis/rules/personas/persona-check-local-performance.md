---
id: persona-check-local-performance
type: persona
domain: efficiency
enforcement: advisory
hypothesis: "Repeated ledger reads or per-consumer parsing add avoidable work and can mix inconsistent evidence snapshots."
prediction: "A growing repository or rule set can multiply I/O, parsing and subprocess startup without changing useful coverage."
falsification: "Revisit when a reviewed public contract replaces the stated behavior or the cited regression no longer tests its failure."
minimum_mode: patrol
tags: [project-contract, v4.5]
target_paths:
  - "aegis_core/scan.py"
  - "aegis_core/fitness.py"
  - "aegis_core/telemetry_engine/ledger.py"
  - "aegis_core/ast/session.py"
  - "aegis_core/ast/batch.py"
---
## Do
Reuse one coherent ledger view and check-local AST results, including failures; bound retained data and driver startup while preserving fresh evidence between separate calls.

Keep caches scoped to the declared check/request and invalidate by actual source/content identity. Batch only compatible ordered work and close owned resources at pass end. Do not obtain speed by skipping governed files, ignoring errors, raising limits or changing accepted policy.

Verify: Use deterministic read/parse/startup counters and output parity with active files/rules; measure timing separately with the existing benchmark protocol and explicit source identity.

Owner instructions and existing approval/release boundaries remain authoritative.

## Evidence
- tests/unit/core/test_scan_ledger_reads.py pins bounded ledger reads and coherent snapshots while fresh calls observe later appends.
- aegis_core/ast/session.py caches each requested AST, including failures, for one check.
- aegis_core/ast/batch.py reuses a bounded sequential driver process.
