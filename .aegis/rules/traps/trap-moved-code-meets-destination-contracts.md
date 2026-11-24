---
id: trap-moved-code-meets-destination-contracts
domain: architecture
type: trap
enforcement: advisory
hypothesis: Code moved into a package from a location outside its structural contracts fails those contracts when the old construction is copied unchanged.
prediction: "Running the destination's contract tests on the moved code before the long qualification run surfaces every such failure locally."
falsification: Retire if ten moves into contract-scanned packages each pass the destination contracts with the old construction unchanged.
expiry_sessions: 15
expiry_days: 60
created: "2026-11-24T19:07:54Z"
impact_weight: 1.0
tags:
  - architecture
  - refactoring
target_paths:
  - "aegis_core/**"
  - "aegis_cli/**"
  - "aegis_mcp/**"
  - "tools/**"
lineage:
  parent_id: null
  created_by: manual
  generation: 0
  siblings: []
---
## Do

Before moving code into a package, list the structural contracts that scan the destination (single process or Git runner, import boundaries, reader and writer inventories, module size) and run them on the moved code. Code that lived outside those contracts has no exception to carry with it.

When the moved code does something a contract routes through one place, design the conforming route first. If the shared route lacks a capability the moved code needs, stop and specify the smallest addition to the shared route; do not add an allowlist entry, rename the call, or keep a second route.

Run the destination's contract tests locally before requesting the long qualification run.

## Evidence

- 2026-11-24 — A parity move of job admission and execution code from a tools directory into the core package passed its local gates and then failed two contract tests in the long run: two native Git command constructions outside the single Git transport, and an unreviewed mailbox reader import. The old location was outside both contracts. The reader inventory needed five reviewed entries; the Git constructions needed a new launch mode in the transport, which cost a design round after the run.

Catalog comparison: nearest are trap-layer-violation (imports across layers) and trap-new-core-module-registry-rows (registry rows for new modules); neither covers moved code meeting contracts that its old location was exempt from.
