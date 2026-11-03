---
id: contract-jit-rule-delivery
type: contract
domain: correctness
enforcement: advisory
hypothesis: "Rule quality depends on the guidance an agent actually receives under production selection limits."
prediction: "Broad mandatory rules or truncated details can hide the specific lesson despite apparently complete coverage."
falsification: "Revisit when a reviewed public contract replaces the stated behavior or the cited regression no longer tests its failure."
minimum_mode: patrol
tags: [project-contract, v4.5]
target_paths:
  - "aegis_core/scan.py"
  - "aegis_core/match.py"
  - "aegis_core/rules.py"
  - "aegis_core/rule_integrity.py"
  - ".aegis/rules/**"
  - "rules/**"
---
## Do
Validate rule loading, matching and actual default-budget JIT delivery separately; a rule that exists or matches is not guaranteed to be served, and prose guidance is not deterministic code enforcement.

Preserve reviewed-base integrity for binding rules, mandatory-slot caps, token accounting and explicit omission metadata. Keep instructions concise and source-scoped, evidence outside the served prefix, and rule ID/type/path metadata consistent. Do not invent fitness to improve rank.

Verify: Exercise real selection with cold-start rules and competing guidance, exact/glob paths, future files, invalid rules, empty targets and token limits. Review scope/tier reductions as governance weakening.

Owner instructions and existing approval/release boundaries remain authoritative.

## Evidence
- aegis_core/scan.py ranks exact matches within fitness/tier limits and caps mandatory slots.
- The read-only audit reproduced identical broad guidance for workspace binding, scan, test execution and outcome paths while 9-12 mandatory matches were omitted.
- tests/unit/core/test_rule_lint.py verifies metadata/target validity; project delivery regressions verify actual selected guidance.
