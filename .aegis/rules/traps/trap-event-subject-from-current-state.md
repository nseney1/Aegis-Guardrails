---
id: trap-event-subject-from-current-state
domain: correctness
type: trap
enforcement: advisory
hypothesis: An event or report line that reads its subject from mutable current state names the wrong item once that state moves on.
prediction: Reading the subject from the record being described keeps the line correct however much later it is printed.
falsification: Retire if ten event emitters each print the recorded subject in a test that changes current state before printing.
expiry_sessions: 15
expiry_days: 60
created: "2026-11-24T12:23:53Z"
impact_weight: 1.0
tags:
  - status_reporting
  - python_file_modification
target_paths:
  - "aegis_core/team_*events.py"
  - aegis_core/events.py
  - "tools/hierarchy_*.py"
lineage:
  parent_id: null
  created_by: manual
  generation: 0
  siblings: []
---
## Do

Event and report lines take their subject (item, lane, commit) from the record they describe, never from mutable current state.

Reading the subject from the record being described keeps the line correct however much later it is printed.

Store the subject in the record when the event happens. Test by changing the current assignment between the event and the print.

## Evidence

- 2026-11-24 — Three merge events named the item the lane had claimed next instead of the merged one, and a merge-triggered duty repeated the wrong item.

Catalog comparison: extends trap-status-without-receipt to the subject of the line.
