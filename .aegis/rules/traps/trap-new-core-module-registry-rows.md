---
id: trap-new-core-module-registry-rows
domain: architecture
type: trap
enforcement: advisory
hypothesis: "A new core module added without its layer row, and without its redaction-importer row when it imports redaction, fails the registry contracts only after the remote qualification run."
prediction: Declaring the rows and their reasons in the handoff lets the registry owner apply them before qualification.
falsification: Retire if ten new core modules each reach qualification with their registry rows already applied.
expiry_sessions: 15
expiry_days: 60
created: "2026-11-24T12:23:49Z"
impact_weight: 1.0
tags:
  - module_creation
  - python_file_creation
target_paths:
  - "aegis_core/*.py"
  - tests/contract/test_import_boundary.py
lineage:
  parent_id: null
  created_by: manual
  generation: 0
  siblings: []
---
## Do

When you add an aegis_core module, declare its registry rows in the handoff: the CORE_LAYERS layer and, if it imports redaction, the REVIEWED_REDACTION_IMPORTERS row, each with its reason.

Declaring the rows and their reasons in the handoff lets the registry owner apply them before qualification.

Registry tables are shared files. List the exact rows as plain lines so the table owner can apply them; do not edit a table another change holds.

## Evidence

- 2026-11-24 — Four consecutive parts that each added a core module stopped at the same registry contracts because the rows were not named in their handoffs.

Catalog comparison: no existing rule names the registry rows a new core module owes.
