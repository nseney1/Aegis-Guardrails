---
id: trap-stale-handoff
type: trap
enforcement: advisory
domain: correctness
hypothesis: "A valid checkpoint can omit a standing brief or carry a ruling that has been superseded."
prediction: "Comparing the outgoing obligations with the successor's bound checkpoint will expose a dropped or stale reference."
falsification: "Retire if ten handoffs involving pruned briefs independently preserve every sampled open duty and superseding ruling."
target_paths:
  - tools/hierarchy_handoff.py
triggers:
  - handoff
  - checkpoint
minimum_mode: patrol
expiry_sessions: 50
expiry_days: 180
created: 2026-11-23
---

## Do

Resolve each open obligation and standing brief against the checkpoint the
successor will actually receive, and surface missing or superseded references
before recording the handoff as complete.

Comparing the outgoing obligations with the successor's bound checkpoint will
expose a dropped or stale reference.

Use the bound checkpoint when checking what the successor can actually read.

## Evidence

The existing trap synchronizes user documentation with features. The handoff
tool's governing-plan branch prunes inherited briefs, so a draft preview can
differ from the bound checkpoint.

- 2026-11-16 — Claimed the destination briefs covered five lessons without reading them. Five addenda were needed (coordinator decision log).
- 2026-11-19 — Left owner decisions out of the carried backlog. Fourteen rows were restored in the second pass (coordinator decision log).

Catalog comparison: new.
