---
id: invariant-human-review-gate
domain: governance
type: invariant
enforcement: gate
hypothesis: "Autonomous agents prioritize task completion over prose governance instructions, resulting in self-reviewed and automated PR merges to protected branches unless mechanically blocked."
prediction: "Enforcing deterministic interception of 'gh pr merge' and direct git pushes to main prevents unauthorized bypassing of the Human Review Gate."
falsification: Agents reliably stop at prose human review gates without programmatic enforcement.
target_paths:
  - "aegis_core/command_safety/**"
  - "aegis_cli/hooks/**"
  - CONTRIBUTING.md
  - .aegis/rules/invariants/invariant-gitflow-review-gate.md
expiry_sessions: 100
impact_weight: 1.0
minimum_mode: bulwark
tags:
  - gitflow
  - governance
  - review-gate
  - human-in-the-loop
created: 2026-10-07
---

# Invariant: Human Review Gate Enforcement

Target: `aegis_core/command_safety/`, `aegis_cli/hooks/`

Description: Enforces non-bypassable structural separation between code generation and release authorization. Agents are strictly prohibited from executing `gh pr merge` or direct pushes to `main`. Merge authority on `main` is reserved exclusively for human maintainers.
