---
id: invariant-dogfood-own-tools
domain: governance
type: invariant
enforcement: gate
hypothesis: "A governance framework that doesn't use its own tools to manage itself loses credibility and misses dogfooding feedback loops that surface UX gaps"
prediction: "Will fire when manual file operations (mv, cp, sed, manual frontmatter edits) are used instead of aegis CLI commands (promote, demote, init, checkpoint) for operations that aegis provides tooling for"
falsification: "If aegis CLI lacks a needed operation for 5 consecutive sessions, the missing operation should be built rather than this rule pruned"
target_paths:
  - ".aegis/rules/**"
  - "aegis_cli/rule.py"
  - "aegis_core/lifecycle/**"
triggers:
  - rule_creation
  - rule_promotion
  - rule_demotion
  - lifecycle_change
minimum_mode: patrol
expiry_sessions: 50
expiry_days: 180
created: 2026-09-30
impact_weight: 1.0
tags:
  - governance
  - dogfooding
  - process
  - meta
---
## Do
Prefer supported Aegis lifecycle tools; an explicit owner-authorized exception may use direct rule-file edits with loader, delivery and governance validation.

Preserve the current validated rule format and approval boundary. Do not invent unsupported lifecycle flags or add an unreleased rule-creation workflow merely to complete an authorized manual change.

Verify: Load the final rule inventory, exercise actual JIT selection, inspect scope/tier changes and obtain the required independent maintainer approval.

Owner instructions override the default lifecycle-tool preference for the stated scope.

## Evidence
- aegis_cli/rule.py and aegis_core/lifecycle/creation.py expose the supported lifecycle surface.
- CONTRIBUTING.md documents current rule authoring and signed-governance review.
- The owner explicitly authorized direct rule-file edits for this repair while creation is reworked for 4.6.
