---
id: trap-missing-operand-reads-stdin
domain: correctness
type: trap
enforcement: advisory
hypothesis: A tool invoked with an empty variable or an unmatched pattern as its file operand falls back to standard input and blocks instead of failing.
prediction: Resolving the operand to a readable file first and disconnecting standard input turns the hang into an immediate named error.
falsification: "Retire if ten file-reading tool invocations each fail at once on a missing operand in tests, with standard input disconnected."
expiry_sessions: 15
expiry_days: 60
created: "2026-11-24T13:16:38Z"
impact_weight: 1.0
tags:
  - correctness
  - portability
target_paths:
  - "aegis_core/**"
  - "tools/**"
  - "aegis_cli/**"
lineage:
  parent_id: null
  created_by: manual
  generation: 0
  siblings: []
---
## Do

Resolve every file operand to an existing readable file before starting a tool that reads standard input when it has no operand. An empty variable or a pattern that matches nothing is an error that names what was looked up, never an empty argument list.

Run such tools with standard input disconnected, so a missing operand fails at once and cannot wait on a terminal or a pipe.

Keep "the file exists and has no match" distinguishable from "the file was not found".

## Evidence

- 2026-11-17 — A search over a brief whose path pattern matched no file read standard input and hung until an operator stopped it.
- 2026-11-17 — A second stdin-reading search hung the same way later that day.

Catalog comparison: nearest is trap-empty-gate-input-passes, which covers empty input read as success, not a missing operand that blocks on standard input.
