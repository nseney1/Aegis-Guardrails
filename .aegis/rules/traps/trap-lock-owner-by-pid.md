---
id: trap-lock-owner-by-pid
domain: correctness
type: trap
enforcement: advisory
hypothesis: Code that decides who owns a lock by comparing a process id from a lock table or pid file misjudges a lock inherited by a child process.
prediction: Deciding ownership from the descriptor this process holds lets an inherited lock proceed and still refuses a foreign holder.
falsification: Retire if ten lock-ownership checks each pass an inherited-lock test and a foreign-holder test.
expiry_sessions: 15
expiry_days: 60
created: "2026-11-24T15:12:19Z"
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

Decide lock ownership from what this process holds: an open descriptor on the lock file (same device and inode) on which it holds the lock. Never look up the owner by process id in a kernel lock table or a pid file.

A lock taken by a parent and inherited by a child stays attributed to the parent in the kernel's table, so a pid comparison calls the rightful owner a stranger.

Test the inherited case: a parent takes the lock, a detached child inherits it and proceeds; a different process holding it is refused.

## Evidence

- 2026-11-24 — A delivery change compared the lock table's process id with its own; with the lock inherited by a detached child every unattended run waited on "busy" until it timed out. Twelve tests failed for that one cause.

Catalog comparison: nearest is trap-overlapping-transition, which covers repeated coordinator actions, not lock attribution.
