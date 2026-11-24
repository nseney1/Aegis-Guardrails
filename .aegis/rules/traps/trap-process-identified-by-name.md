---
id: trap-process-identified-by-name
domain: correctness
type: trap
enforcement: advisory
hypothesis: Supervision code that finds its processes by script name or command-line substring also matches unrelated copies and its own caller.
prediction: Matching on a recorded identity or the exact argument vector with the resolved root counts only the processes it started.
falsification: Retire if ten process censuses each ignore a decoy with the same script name started from another root.
expiry_sessions: 15
expiry_days: 60
created: "2026-11-24T15:12:20Z"
impact_weight: 1.0
tags:
  - correctness
  - python_file_modification
target_paths:
  - "aegis_core/**"
  - "aegis_cli/**"
  - "tools/**"
lineage:
  parent_id: null
  created_by: manual
  generation: 0
  siblings: []
---
## Do

Identify the processes you supervise by an identity you created: a recorded process id with its start time, or the exact argument vector including the resolved root you launched it from. Never by script name or a substring of the command line.

A name match also catches copies of the same program started by tests, reviewers or another checkout, and then holds gates open or stops the wrong process.

Test with a decoy: the same script name started from a different root must not be counted.

## Evidence

- 2026-11-24 — A drain census counted a reviewer's fixture processes, started from a temporary copy with the same script name, as live jobs and would have blocked an installation gate.
- 2026-11-22 — A helper's busy check matched its own shell command line because the line contained the name it searched for.

Catalog comparison: nearest is trap-unobserved-work, which covers work nobody watches, not misidentified processes.
