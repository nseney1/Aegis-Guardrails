---
id: trap-shared-shape-consumers-unselected
domain: testing
type: trap
enforcement: advisory
hypothesis: A change to a shared return shape or a published schema breaks consumers that the focused test selection does not include.
prediction: "Selecting every consumer, including test stubs and byte or hash pins, shows the breakage before the full run."
falsification: Retire if ten shape or schema changes each reach the full run with no failure outside their requested selection.
expiry_sessions: 15
expiry_days: 60
created: "2026-11-24T12:23:51Z"
impact_weight: 1.0
tags:
  - python_file_modification
  - test_modification
target_paths:
  - "aegis_core/**"
  - "aegis_mcp/**"
  - "aegis_cli/**"
lineage:
  parent_id: null
  created_by: manual
  generation: 0
  siblings: []
---
## Do

When a change alters a returned object's attributes or an MCP or CLI schema, find every consumer, including test stubs and byte or hash pins, and put them in the requested test selection.

Selecting every consumer, including test stubs and byte or hash pins, shows the breakage before the full run.

Search for the attribute and schema names across the product and the tests, and list the files found in the handoff so the reviewer can check the selection.

## Evidence

- 2026-11-24 — A change to a rule object and a tool schema passed its focused selection and failed the full run on test stubs and a tools-list byte pin outside that selection.

Catalog comparison: no existing rule ties shape changes to consumer selection.
