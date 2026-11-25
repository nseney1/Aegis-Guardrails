---
id: trap-shared-table-entry-at-common-position
domain: architecture
type: trap
enforcement: advisory
hypothesis: Entries added by different branches at the same position of a shared table conflict textually even when they are unrelated.
prediction: Adding each entry at its sorted or separated position lets concurrent branches merge without a manual step.
falsification: Retire if ten concurrent additions to one shared table at its first position each merge without a conflict.
expiry_sessions: 15
expiry_days: 60
created: "2026-11-24T16:33:23Z"
impact_weight: 1.0
tags:
  - review
  - test_creation
target_paths:
  - "tests/contract/**"
  - "tests/unit/core/**"
lineage:
  parent_id: null
  created_by: manual
  generation: 0
  siblings: []
---
## Do

When you add an entry to a table that several branches extend (a registry, an allowlist, an ordered list of reviewed sites), put it at its sorted position, or at least where an unchanged line separates it from the table's first and last entries. Do not insert directly after the opening line or directly before the closing line.

Two branches that insert at the same position conflict textually even when their entries are unrelated, and the later one needs a manual merge. Entries in sorted or separated positions merge cleanly.

Before adding the entry, look at where other open branches added theirs to the same table, and keep any order the table's tests require.

## Evidence

- 2026-11-24 — Several branches each needed new entries in the same reviewed-operations tables. One set was inserted directly after the opening line of two tables. A check of the other branches showed that the next branch planned the same position, so its entries were placed in sorted position instead; a three-way merge check across 24 branches then reported no conflicts.

Catalog comparison: nearest is trap-new-core-module-registry-rows (remembering that an entry is needed); it does not cover where the entry goes.
