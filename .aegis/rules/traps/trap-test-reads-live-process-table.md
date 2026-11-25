---
id: trap-test-reads-live-process-table
domain: testing
type: trap
enforcement: advisory
hypothesis: "A test that reads the machine's live process table passes or fails with whatever else happens to be running on that machine."
prediction: Injecting the process listing into the code under test makes the result independent of host activity while one narrow test still covers the real reader.
falsification: Retire if in fifty runs on busy shared hosts no process-reading test changes its outcome with host activity.
expiry_sessions: 15
expiry_days: 60
created: "2026-11-25T13:02:24Z"
impact_weight: 1.0
tags:
  - testing
  - hermeticity
target_paths:
  - "tests/**"
  - "aegis_core/**"
  - "tools/**"
lineage:
  parent_id: null
  created_by: manual
  generation: 0
  siblings: []
---
## Do

A test of code that reads the process table must supply the process listing itself, through a parameter or a seam the code already reads, so the result depends only on the fixture.

This covers censuses, supervisor checks and "still running" probes. Keep one narrow test that exercises the real reader on a process the test starts and owns.

Write the fixture listing so a name match that the real code treats as a conflict is present in one case and absent in another, and assert both outcomes. A test that passes only because the machine happened to be quiet proves nothing.

## Evidence

On 2026-11-25 a gate test that expected "no daemon visible" failed on every run on the coordinator host, because 24 live slot daemons matched the gate's name-based census. The author's sandbox could not see host processes, so the same test had passed there. Injecting the listing made it pass in both places and kept the fail-closed census covered.
