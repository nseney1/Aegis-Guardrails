---
id: contract-process-custody-identity
domain: security
type: contract
enforcement: advisory
hypothesis: "Custody that identifies processes by PID/PGID alone, or clears custody on exception paths, loses or misattributes live descendants (PID reuse, process-group change, no pidfd, reboot or namespace change)."
prediction: "Tests that recycle a PID, move a descendant to a new process group, or raise during construction show custody released or the wrong process signalled."
falsification: "Revisit when custody records carry boot id, PID namespace and start time (or a pidfd) under such a matrix, with fewer than 5 findings in 14 days."
expiry_sessions: 15
expiry_days: 60
created: "2026-11-26T02:44:58Z"
impact_weight: 1.0
tags:
  - review-audit-20261126
  - security
target_paths:
  - "aegis_core/team_session_*.py"
  - "aegis_core/team_supervisor*.py"
  - tools/hierarchy_launcher.py
  - tools/hierarchy_team.py
  - tools/hierarchy_sweep.py
  - "tests/integration/test_hierarchy_launcher*.py"
  - tests/integration/test_hierarchy_sweep.py
lineage:
  parent_id: null
  created_by: manual
  generation: 0
  siblings: []
---
## Do
Identify processes by pid plus start time (or a pidfd), never by pid alone. Signal through a pidfd or a verified process group, account for descendants, and treat a vanished or reused pid as unknown, not as the original process.

Verify: PID-reuse, orphaned-descendant and process-group fixtures keep custody correct or refuse.

Owner instructions and existing approval/release boundaries remain authoritative.

## Evidence
- Formal review history 2026-11-11 to 2026-11-25: about 202 blocking findings in this class across 25 lanes (keyword classification of 1,385 REQUEST CHANGES reviews; approximate).
- grok-b, 2026-11-14, P1: persisted identities lack boot and PID-namespace scope.
- pr6, 2026-11-15, P1: detached descendants escape custody.
- strip-fix, 2026-11-18, P1: concurrent cleanup can signal a recycled PID.
- grok-e, 2026-11-19, P1: descendants escape by changing process group.
- codex-a, 2026-11-16, P1: a refused replacement bind leaves false death evidence.
- Why existing rules did not cover it: `contract-ast-driver-lifecycle` requires process ownership and cleanup, but only for `aegis_core/ast/{batch,runner,gobuild,windows_job}.py`.
