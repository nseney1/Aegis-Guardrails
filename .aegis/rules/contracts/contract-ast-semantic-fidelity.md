---
id: contract-ast-semantic-fidelity
type: contract
domain: correctness
enforcement: advisory
hypothesis: "Portable AST rules remain correct only when normalization preserves the semantics used by policy evaluation."
prediction: "Literal spelling, shadowing or missing capabilities can turn a real violation into an apparent absence."
falsification: "Revisit when a reviewed public contract replaces the stated behavior or the cited regression no longer tests its failure."
minimum_mode: patrol
tags: [project-contract, v4.5]
target_paths:
  - "aegis_core/ast/policy.py"
  - "aegis_core/ast/schema.py"
  - "aegis_core/ast/literals.py"
  - "aegis_core/ast/source.py"
  - "aegis_core/ast/drivers/**"
---
## Do
Preserve language meaning across normalized ASTs: distinguish unknown from false, honor source encodings and lexical binding, and never treat unsupported or failed analysis as a clean code verdict.

Preserve numeric/string literal types, alias scope, overwrite/spread order and declared driver capabilities. Use the shared safe source decoder for current and historical Python bytes; language selection and unavailable-driver status remain explicit.

Verify: Use public evaluation/check results for equivalent literal forms, shadowed aliases, missing arguments/capabilities, invalid encodings, malformed code and unsupported/configured-unavailable drivers.

Owner instructions and existing approval/release boundaries remain authoritative.

## Evidence
- aegis_core/ast/policy.py uses tri-state predicates and capability-aware argument checks; literals.py handles semantic literal comparison.
- aegis_core/ast/source.py handles BOM/coding cookies and refuses unsafe/nontransparent source encodings.
- tests/unit/core/test_ast_policy_m1.py and test_no_driver_m1.py cover policy and no-driver outcomes.
