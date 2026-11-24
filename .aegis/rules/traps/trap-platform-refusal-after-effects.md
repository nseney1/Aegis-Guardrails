---
id: trap-platform-refusal-after-effects
domain: correctness
type: trap
enforcement: advisory
hypothesis: "An unsupported-platform refusal issued after a marker, state file, lock or child process exists leaves effects behind."
prediction: Refusing before the first effect leaves the workspace and process table unchanged on unsupported platforms.
falsification: Retire if ten reviewed platform refusals all return before any filesystem or process effect.
expiry_sessions: 15
expiry_days: 60
created: "2026-11-24T12:23:48Z"
impact_weight: 1.0
tags:
  - python_file_modification
  - feature_addition
target_paths:
  - tools/hierarchy_wake.py
  - "aegis_core/team_*.py"
lineage:
  parent_id: null
  created_by: manual
  generation: 0
  siblings: []
---
## Do

Decide platform support before any effect: an unsupported-platform refusal returns before the code writes an exclusion marker, state file or lock, or starts a child process.

Refusing before the first effect leaves the workspace and process table unchanged on unsupported platforms.

Order the checks so that every refusal which needs no effect comes first. Test the refusal by asserting that the directory contents and the process table are unchanged afterwards.

## Evidence

- 2026-11-24 — A wake helper refused an unsupported platform after writing its exclusion marker; the marker stayed behind and the change returned from review for it.

Catalog comparison: no existing rule orders platform refusals before effects.
