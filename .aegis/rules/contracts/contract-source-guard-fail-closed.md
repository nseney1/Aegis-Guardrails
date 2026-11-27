---
id: contract-source-guard-fail-closed
domain: testing
type: contract
enforcement: advisory
hypothesis: "Source-scanning ratchets that recognise forbidden calls by their written names admit ordinary Python binding routes (import aliases, starred calls, container copies, re-exports, subclass/mixin lookup), so each fix round adds one spelling and the next review finds another."
prediction: A guard change that adds recognised spellings without refusing unresolved bindings draws a new alias/rebinding finding in the next formal review.
falsification: "Revisit if 10 consecutive guard-touching deliveries pass formal review with no binding-route finding, or if this class falls below 5 findings per 14 days after guards refuse unresolved names."
expiry_sessions: 15
expiry_days: 60
created: "2026-11-26T02:44:49Z"
impact_weight: 1.0
tags:
  - review-audit-20261126
  - testing
target_paths:
  - tests/contract/test_process_ratchets.py
  - tests/contract/test_mailbox_refusal_reasons.py
  - tests/contract/test_refusal_inventory_analyzer.py
  - tests/conftest.py
  - "tests/helpers_*.py"
lineage:
  parent_id: null
  created_by: manual
  generation: 0
  siblings: []
---
## Do
Source-scanning guards and ratchets resolve bindings, not spellings. Treat import aliases, starred calls, container copies, re-exports and subclass or mixin lookup as the guarded call. When a binding cannot be resolved statically, refuse (fail closed) or move the check to a runtime seam. Do not answer a binding-route finding by adding one more recognised spelling.

Verify: fixtures for an alias, a starred call, a re-export and a subclass route each fail the guard, and an unresolved binding is refused.

Owner instructions and existing approval/release boundaries remain authoritative.

## Evidence
- Formal review history 2026-11-11 to 2026-11-25: about 389 blocking findings in this class across 23 lanes (keyword classification of 1,385 REQUEST CHANGES reviews; approximate).
- grok-b, 2026-11-18, P2: ordinary import aliases bypass the contract.
- grok-a, 2026-11-15, P1: sequence transformations erase stored callables.
- codex-b, 2026-11-18, P2: structural guard admits ordinary module aliases.
- grok-e, 2026-11-17, P2: starred storage targets bypass the mutation census.
- t-alpha, 2026-11-21, P1: mutator calls bypass origin review.
- Why existing rules did not cover it: no rule's `target_paths` names these guard files. `trap-tautological-test` and `trap-happy-path-only-tests` do reach `tests/**`, but they are about assertion quality and negative cases, not whether an analyzer is sound. `contract-ast-semantic-fidelity` covers lexical binding only under `aegis_core/ast/**`.
