---
id: trap-doc-feature-drift
domain: documentation
type: trap
enforcement: advisory
hypothesis: "Adding or modifying a feature without updating ALL documentation surfaces (README, CHANGELOG, SKILL.md) in the same commit causes doc-feature desync"
prediction: "Will fire when a commit touches code files but not documentation, or updates one doc surface but not others"
falsification: 0 findings in 20 sessions → prune
target_paths:
  - README.md
  - "docs/*.md"
  - "skills/*/SKILL.md"
  - "aegis_cli/*.py"
  - "aegis_mcp/*.py"
triggers:
  - feature_addition
  - feature_modification
  - commit_review
minimum_mode: patrol
expiry_sessions: 30
expiry_days: 90
created: 2026-09-30
impact_weight: 1.0
tags:
  - documentation
  - drift
  - process
---

Citadel doc-drift incident: Citadel intensity added to README and SKILL.md but
CHANGELOG v0.60.0 was not updated. Architecture ASCII box was edited but not
width-verified. Detection: when a commit adds a feature term to any doc, grep all
other doc surfaces for the same term.
