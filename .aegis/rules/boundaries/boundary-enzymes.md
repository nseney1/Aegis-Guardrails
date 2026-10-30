---
id: boundary-enzymes
domain: governance
type: boundary
enforcement: advisory
hypothesis: Core modules and workflows dictate agent behavior.
prediction: Bulwark mode enforcement here guarantees safe behavior modification.
falsification: Core modules are purely descriptive and have no operational power.
target_paths:
  - "aegis_core/governance.py"
  - "aegis_core/rule_integrity.py"
  - ".github/workflows/**"
expiry_sessions: 80
impact_weight: 1.0
minimum_mode: bulwark
tags:
  - core
  - workflows
  - review-escalation
created: 2026-09-28
---
## Do
Review changes to governance authorization and trusted workflow execution as security-sensitive policy changes, with explicit trust-boundary and approval evidence.

Keep release, signing and CI credentials outside pull-request authority. Use the base branch's governance implementation when reviewing a candidate tree; do not claim a higher review mode label itself executes or enforces a check.

Verify: Exercise public governance decisions and affected trusted workflow paths; distinguish local validation, independent review, signed approval and hosted CI.

Owner instructions and existing approval/release boundaries remain authoritative.

## Evidence
- CONTRIBUTING.md documents base-sourced governance review and maintainer signature custody.
- aegis_core/governance.py and rule_integrity.py implement policy comparison; workflow files define trusted execution.
