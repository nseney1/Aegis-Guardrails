---
id: invariant-decomposition-merge-gate
domain: architecture
type: invariant
enforcement: gate
hypothesis: "A decomposition that relocates code without pinning behavior (compat shims, duplicate handlers, import-time patching, abstractions without consumers) breaks public names and hides regressions behind size-only tests"
prediction: "A decomposition PR merges only with the full suite green at HEAD, a pre-branch public-name compat test, one definition per handler and its CHANGELOG and ADR entries"
falsification: "0 findings in 15 sessions: prune"
expiry_sessions: 15
expiry_days: 60
created: "2026-10-15T16:11:59Z"
impact_weight: 1.0
tags: ["debrief", "citadel", "refactor", "compat"]
target_paths:
  - "CONTRIBUTING.md"
  - "tests/contract/public_names_4_3_3.json"
  - "tests/contract/test_import_boundary.py"
  - "CHANGELOG.md"
lineage:
  parent_id: null
  created_by: "manual"
  generation: 0
  siblings: []
---
# Invariant: a decomposition merges only with its behavior pinned

**Rule**: A refactor that moves or splits modules is mergeable only when the
full suite is green at HEAD; a compat test proves the pre-branch public names
still resolve, or the CHANGELOG lists each removal under BREAKING CHANGE; each
handler has exactly one definition, with no import-time patching and no
`__class__` swaps; every new abstraction has a production consumer; size gates
count formatter-normalized lines and per-function complexity; and behavior
changes ship with their CHANGELOG and ADR entries in the same PR.

The debrief classed this rule as `gate`. It is created as an invariant with
`enforcement: gate`, because `gate` is the top of the trap -> invariant -> gate
ladder and is reached by review (`aegis rule promote`, D1), not by
`aegis rule create`.

## Incident (v4 Citadel review)

- The v4 decomposition dropped 21 module attributes from the
  `aegis_core.telemetry` facade (suite red at HEAD). It kept and widened a
  `__class__`-swap module proxy from 2 to 5 mirrored modules, duplicated handlers
  in `aegis_mcp/handlers/governance.py` and `handlers/telemetry.py` that were
  patched at import inside `except: pass`, and left permanent aliases
  (`CellInventory`, `find_matching_cells`) with two import paths.
- It added `WorkspaceLayout` with no production consumer, moved release-gate
  logic into CLI formatters and packed lines in `yaml_engine/parser.py` to meet
  a 350-line gate. Hotspot cyclomatic complexity rose 4.4%, and the docs,
  changelog and ADRs were not updated.
- It was missed because the new tests asserted module size, re-export identity
  and key membership (13 of 106 mutants killed), no test enumerated the
  pre-branch public names, and the branch never ran the full suite or CI before
  review.

## Check

1. Run the full suite at the PR head and CI on the exact SHA, not only the
   touched tests.
2. Compare `dir(module)` for every moved public module between the merge base
   and HEAD; each missing name is restored or listed under BREAKING CHANGE.
3. No `__class__ =` or `sys.modules[...] =` assignment in `aegis_*`, and no
   handler name defined in two handler modules.
4. Every new class or module has a non-test importer.
