---
id: invariant-core-change-protocol
domain: governance
type: invariant
enforcement: gate
hypothesis: "A bug in fitness scoring, rule lifecycle or verification verdicts corrupts the governance layer's ability to detect later bugs, so changes there need the full TDD protocol with no trivial-change exemption"
prediction: "Every change under the target paths lands with tests written first and stated red and green evidence"
falsification: "Over 20 changes to these paths, changes made without the TDD protocol escape no more defects than changes made with it"
expiry_sessions: 15
expiry_days: 60
created: "2026-10-15T16:18:02Z"
impact_weight: 1.0
tags: ["dogfood", "process", "tdd"]
target_paths: ["aegis_core/outcomes/**", "aegis_core/lifecycle/**", "aegis_core/fitness.py", "aegis_core/rules.py", "aegis_core/match.py", "aegis_core/scan.py", "aegis_core/sync.py", "aegis_core/verification/**", "aegis_core/redaction.py", "aegis_cli/hooks/**"]
lineage:
  parent_id: null
  created_by: "manual"
  generation: 0
  siblings: []
---
# Core Rule & Skill Change Protocol

**Activation**: Changes touching: aegis_core/outcomes/*, aegis_core/lifecycle/*, aegis_core/{fitness,rules,match,scan,sync}.py, aegis_core/verification/*, aegis_cli/hooks/*

Sensitive governance systems **must** follow the full TDD Protocol
(see `rules/.oracles/tdd-protocol.md`) without exception.

These files control rule fitness scoring, rule lifecycle, and verification verdicts.
A bug here doesn't just break a feature — it corrupts the governance layer's ability
to detect future bugs. The blast radius is recursive.

No trivial-change exemption applies to files in this activation list.
